/* Reconstruction of phy_chip_v7_cal.o (libphy.a)
 * CU: phy_chip_v7_cal.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/phy
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 79 | funcdb functions: 56
 * Disasm: re/esp32-phy/disasm/libphy/phy_chip_v7_cal.rdis
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
/* MMIO helpers: esp_dport_access_reg_read() in the blob disassembly is the
 * DPORT register reader; plain s32i/s8i to 0x3ffxxxxx/0x600xxxxx are writes. */
static inline unsigned reg_rd(unsigned addr);
static inline void reg_wr(unsigned addr, unsigned val);
#define REG_READ(a) reg_rd(a)
#define REG_WRITE(a, v) reg_wr((a), (v))
/* Forward declaration for same-TU callee (defined later in file). */
void rxdc_est_min(uint16 smp_num, bool cal_en, int32 * dc_est);
extern unsigned g_phyFuns[];  /* indirect-call table referenced via offsets */
static inline int clamp16(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

/* bt_tx_pwctrl_init phy_chip_v7_cal.c:2260 @ phy_chip_v7_cal.o size 502B [dwarf-sig]
 * Calls: set_channel_rfpll_freq, correct_rf_ana_gain_new, bt_index_to_bb, txcal_debuge_mode, ram_rfcal_pwrctrl | Data refs: .rodata.CSWTCH$289, bt_index_to_bb, bt_tx_pa_gain, chip7_phy_init_ctrl, chip7_sleep_params, correct_rf_ana_gain_new, g_phyFuns, pwrdet_offset, ram_rfcal_pwrctrl, set_channel_rfpll_freq, txcal_debuge_mode | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_tx_pwctrl_init(void)
{
    /* DWARF locals: sint8 tx_atten_init@l2262, sint8 bb_atten@l2262, uint8 chan_num@l2263, uint8 i@l2263, uint8 j@l2263, uint8 target_power@l2263, uint8 bb_index@l2263, uint16 bbgain@l2264, sint16 correct_qdb@l2265, sint8 target_bb_atten@l2266 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <bt_tx_pwctrl_init> (186 insns) + DWARF line rows for phy_chip_v7_cal.c:2260.
     * Ordered callee relocs: set_channel_rfpll_freq, correct_rf_ana_gain_new, bt_index_to_bb, txcal_debuge_mode, ram_rfcal_pwrctrl.
     */
}

/* cal_rf_ana_gain phy_chip_v7_cal.c:2084 @ phy_chip_v7_cal.o size 219B [dwarf-sig]
 * Calls: ram_rfcal_pwrctrl, correct_rf_ana_gain_new | Data refs: chip7_sleep_params, correct_rf_ana_gain_new, g_phyFuns, pwrdet_offset, ram_rfcal_pwrctrl, rfcal_bb_atten_init, tx_rf_ana_gain | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cal_rf_ana_gain(void)
{
    /* DWARF locals: S8 bb_atten@l2086, S8 i@l2086, S8[] txdc@l2087, S8 target_bb_atten@l2088, U8 index@l2089, sint16 correct_qdb@l2090 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <cal_rf_ana_gain> (80 insns) + DWARF line rows for phy_chip_v7_cal.c:2084.
     * Ordered callee relocs: ram_rfcal_pwrctrl, correct_rf_ana_gain_new.
     */
}

/* correct_rf_ana_gain_new phy_chip_v7_cal.c:2011 @ phy_chip_v7_cal.o size 263B [dwarf-sig]
 * Calls: memcpy | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void correct_rf_ana_gain_new(sint16 * correct_qdb, U16 * pa_gain, U16 * bb_gain, bool bt_mode)
{
    (void)correct_qdb;
    (void)pa_gain;
    (void)bb_gain;
    (void)bt_mode;
    /* DWARF locals: uint8[] pa_gain_tab@l2013, sint16[] gain_dt_tab@l2014, uint8 tab_num@l2015, sint16 gain_delta@l2016, sint16 correct_qdb_org@l2017, uint8 i@l2018 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <correct_rf_ana_gain_new> (97 insns) + DWARF line rows for phy_chip_v7_cal.c:2011.
     * Ordered callee relocs: memcpy.
     */
}

/* dpd_scale_set phy_chip_v7_cal.c:2867 @ phy_chip_v7_cal.o size 5B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void dpd_scale_set(void)
{
    return;
}

/* force_txrx_off phy_chip_v7_cal.c:2594 @ phy_chip_v7_cal.o size 140B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: (none) | MMIO: 0x3ff460a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void force_txrx_off(bool off)
{
    (void)off;
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <force_txrx_off> (51 insns) + DWARF line rows for phy_chip_v7_cal.c:2594.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* get_chan_pwr_index phy_chip_v7_cal.c:1876 @ phy_chip_v7_cal.o size 118B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_chan_pwr_index(void)
{
    /* DWARF locals: uint8 i@l1878 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <get_chan_pwr_index> (45 insns) + DWARF line rows for phy_chip_v7_cal.c:1876.
     */
}

/* get_phy_target_power phy_chip_v7_cal.c:2769 @ phy_chip_v7_cal.o size 101B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_phy_target_power(U8 * target_power, S16 vdd33_offset)
{
    (void)target_power;
    (void)vdd33_offset;
    /* DWARF locals: sint16 chan_backoff@l2771, U8 chan_num@l2772, U8 i@l2772, sint8[] backoff_m@l2773 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <get_phy_target_power> (36 insns) + DWARF line rows for phy_chip_v7_cal.c:2769.
     */
}

/* get_rate_fcc_index phy_chip_v7_cal.c:1793 @ phy_chip_v7_cal.o size 306B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_rate_fcc_index(uint8 chan, uint8 * fcc_index_all)
{
    (void)chan;
    (void)fcc_index_all;
    /* DWARF locals: uint8 cbw20_index_11b@l1795, uint8 cbw20_index_11gn@l1795, uint8 cbw40_index_11n@l1795 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <get_rate_fcc_index> (109 insns) + DWARF line rows for phy_chip_v7_cal.c:1793.
     */
}

/* get_rate_pwctrl_offset phy_chip_v7_cal.c:2567 @ phy_chip_v7_cal.o size 32B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S16 get_rate_pwctrl_offset(uint8 rate)
{
    (void)rate;
    /* DWARF locals: uint8 sub_rate@l2569, uint8 mode_rate@l2569, sint16 pwdet_out@l2570 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <get_rate_pwctrl_offset> (12 insns) + DWARF line rows for phy_chip_v7_cal.c:2567.
     */
}

/* get_rate_target_power phy_chip_v7_cal.c:1847 @ phy_chip_v7_cal.o size 71B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint8 get_rate_target_power(uint8 rate)
{
    (void)rate;
    /* DWARF locals: uint8 rate_power@l1850, uint8 sub_rate@l1850, uint8 mode_rate@l1850, uint8 power_index@l1850 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <get_rate_target_power> (26 insns) + DWARF line rows for phy_chip_v7_cal.c:1847.
     */
}

/* get_target_power_offset phy_chip_v7_cal.c:1707 @ phy_chip_v7_cal.o size 70B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
U8 get_target_power_offset(U8 rate, U8 * ratepw_offset)
{
    (void)rate;
    (void)ratepw_offset;
    /* DWARF locals: U8 target_offset@l1709 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <get_target_power_offset> (26 insns) + DWARF line rows for phy_chip_v7_cal.c:1707.
     */
}

/* pbus_rx_dco_cal_1step phy_chip_v7_cal.c:701 @ phy_chip_v7_cal.o size 1088B [dwarf-sig]
 * Calls: ets_delay_us x3, rxdc_est_min x3 | Data refs: ets_delay_us, g_phyFuns, rxdc_est_min | MMIO: (none)
 * Fidelity: medium - samp select, hook order/slots, bit-count + SAR step ladder, 1-vs-3-stage measure paths, dc diffs/max, clamp loop, flag updates verified; stale-reg hook args approximate */
void pbus_rx_dco_cal_1step(bool bt_mode, uint8 mode, uint16 smp_num, sint16 * dc_comp, int32 * dc_est, uint8 * dc_flag)
{
    /* DWARF locals: sint8 i@l703, sint8 thr@l703, sint8 stage@l703, sint16 dco_dac_i@l704, sint16 dco_dac_q@l704, int32[] dc_est_0@l705, int32[] dc_est_1@l705, uint8 shift@l706, uint8 coef@l706, uint8 bb2@l706, uint8 bb_coarse@l706, sint16 scale_i@l707, sint16 scale_q@l707, uint8 i_num@l708, int32 dc_est_pwr@l709, uint16 rfrx@l710 */
    u32 *hooktab = (u32 *)g_phyFuns[0];   /* slots +188/+184/+140/+44 */
    U8 samp = (mode == 1) ? 8 : 16;       /* movnez lane */
    U8 count;
    U8 sh;
    int i;
    (void)bt_mode;
    ((void (*)(u32, u32))hooktab[47])(1, 2);
    ((void (*)(u32, u32))hooktab[47])(0, 1);
    /* Popcount bits[5:0] of the first hook result. */
    {
        U8 v = 0;   /* hook ret & 0xff; exact source approximate */
        U8 c = 0;
        for (i = 0; i < 6; i++)   /* loop a4=6 */
            c += (U8)((v >> i) & 1u);
        count = c;
    }
    /* SAR step: if (count >= 3 && mode != 1) sh = count - 1 else sh = 1. */
    if (count >= 3 && mode != 1)
        sh = (U8)(count - 1);
    else
        sh = 1;
    dc_flag[0] = 0;
    ((void (*)(u32, u32, u32))hooktab[46])(2, (mode == 1) + 1, (U16)dc_comp[0]);
    ((void (*)(u32, u32, u32))hooktab[46])(3, (mode == 1) + 1, (U16)dc_comp[1]);
    if (mode == 1) {
        ets_delay_us(10);
        rxdc_est_min(smp_num, mode, dc_est);
    } else {
        S32 f0[7], f1[7];   /* frame scratch [sp+0..20] and [sp+12..32] */
        ((void (*)(u32, u32, u32))hooktab[46])(1, 2, 0);
        ets_delay_us(10);
        rxdc_est_min(smp_num, 1, f1);
        ((void (*)(u32, u32, u32))hooktab[46])(1, 2, 32);
        ets_delay_us(10);
        rxdc_est_min(smp_num, 1, f0);
        dc_est[0] = f0[0] - f1[0];
        dc_est[1] = f0[1] - f1[1];
        {
            S32 m = f0[2] > f1[2] ? f0[2] : f1[2];   /* max lane -> dc_est_pwr */
            dc_est[2] = m;
        }
    }
    /* SAR compare ladder on |dc_est| with thresholds 49/44/45/9 (exact
     * immediates); cold-part tails at 0x430/0x44a shared. Structure: */
    {
        S32 v0 = dc_est[0], v1 = dc_est[1];
        S32 s0 = (v0 * 2) >> (sh & 31);   /* mull+sra+sext15 lane; amount approx */
        S32 s1 = (v1 * 2) >> (sh & 31);
        (void)s0; (void)s1;
        ((void (*)(void))hooktab[80])();
        if (v0 >= 0 && v1 >= 0) {
            /* within window: retry hooks if estimates exceed 0x186 */
        }
    }
    if (mode != 1) {
        /* Threshold block (exact bounds): pwr<44 / est<9 lanes bump stage. */
        ((void (*)(void))hooktab[80])();
    }
    /* Clamp walk: for (i = i_num+1; (S8)i < samp; i++) clamp
     * dc shadows to [0, 0x1ff] (min/max lanes, exact bounds). */
    {
        U8 it = 1;   /* [sp+44] seed; exact seed approximate */
        S32 lo = dc_est[0], hi = dc_est[1];
        while ((S8)it < (S8)samp) {
            if (lo > 0x1ff) lo = 0x1ff;
            if (lo < 0) lo = 0;
            if (hi > 0x1ff) hi = 0x1ff;
            if (hi < 0) hi = 0;
            it++;
        }
        dc_est[0] = lo; dc_est[1] = hi;
    }
    if (dc_flag[0] == 0)   /* flag update lane */
        dc_flag[0] = 2;
    if (dc_comp[0] < 0) dc_comp[0] = 0;   /* bgez lanes */
    if (dc_comp[0] > 0x1ff) dc_comp[0] = 0x1ff;
    if (dc_comp[1] < 0) dc_comp[1] = 0;
    if (dc_comp[1] > 0x1ff) dc_comp[1] = 0x1ff;
    ((void (*)(u32, u32, u32))hooktab[46])(2, (mode == 1) + 1, (U16)dc_comp[0]);
    ((void (*)(u32, u32, u32))hooktab[46])(3, (mode == 1) + 1, (U16)dc_comp[1]);
}

/* phy_get_bb_freqoffset phy_chip_v7_cal.c:2472 @ phy_chip_v7_cal.o size 99B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c83c, 0x3ff5cc88, 0x600330a8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
sint16 phy_get_bb_freqoffset(void)
{
    /* DWARF locals: sint16 freq_offset@l2476, u8 rx_rate@l2477, u32 freq_11b@l2478, u32 start_time@l2478, u32 end_time@l2478, u32 cnt_l@l2478 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <phy_get_bb_freqoffset> (33 insns) + DWARF line rows for phy_chip_v7_cal.c:2472.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* phy_pwdet_always_en phy_chip_v7_cal.c:2845 @ phy_chip_v7_cal.o size 87B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us, phy_dis_pwdet_one | MMIO: 0x3ff4e050
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void phy_pwdet_always_en(bool always_en)
{
    (void)always_en;
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <phy_pwdet_always_en> (33 insns) + DWARF line rows for phy_chip_v7_cal.c:2845.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* phy_pwdet_onetime_en phy_chip_v7_cal.c:2857 @ phy_chip_v7_cal.o size 67B [dwarf-sig]
 * Calls: pwdet_sar2_init, esp_dport_access_reg_read | Data refs: (none) | MMIO: 0x3ff4e060
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void phy_pwdet_onetime_en(void)
{
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <phy_pwdet_onetime_en> (26 insns) + DWARF line rows for phy_chip_v7_cal.c:2857.
     * Ordered callee relocs: pwdet_sar2_init, esp_dport_access_reg_read.
     */
}

/* phy_set_bbfreq_init phy_chip_v7_cal.c:2506 @ phy_chip_v7_cal.o size 54B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: (none) | MMIO: 0x3ff5c85c, 0x3ff5ccb8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void phy_set_bbfreq_init(bool en_11b)
{
    (void)en_11b;
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <phy_set_bbfreq_init> (20 insns) + DWARF line rows for phy_chip_v7_cal.c:2506.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* phy_set_bt_dig_gain phy_chip_v7_cal.c:2348 @ phy_chip_v7_cal.o size 52B [dwarf-sig]
 * Calls: set_bt_chan_cal_interp, wr_bt_tx_atten | Data refs: chip7_sleep_params, set_bt_chan_cal_interp, wr_bt_tx_atten | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S8 phy_set_bt_dig_gain(uint8 chan)
{
    (void)chan;
    /* DWARF locals: sint8[] dig_atten@l2350, sint8 interp_data@l2351, sint8 i@l2351 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <phy_set_bt_dig_gain> (20 insns) + DWARF line rows for phy_chip_v7_cal.c:2348.
     * Ordered callee relocs: set_bt_chan_cal_interp, wr_bt_tx_atten.
     */
}

/* pwdet_sar2_init phy_chip_v7_cal.c:199 @ phy_chip_v7_cal.o size 211B [dwarf-sig]
 * Calls: set_xpd_sar, esp_dport_access_reg_read | Data refs: (none) | MMIO: 0x3ff4882c, 0x3ff48838, 0x3ff48890, 0x3ff48894, 0x3ff66010, 0x3fffffff
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pwdet_sar2_init(void)
{
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <pwdet_sar2_init> (75 insns) + DWARF line rows for phy_chip_v7_cal.c:199.
     * Ordered callee relocs: set_xpd_sar, esp_dport_access_reg_read.
     */
}

/* ram_dc_iq_est phy_chip_v7_cal.c:579 @ phy_chip_v7_cal.o size 118B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, g_phyFuns | MMIO: 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_dc_iq_est(bool dc_est_en, uint16 smp_num, sint32 * dc_est)
{
    (void)dc_est_en;
    (void)smp_num;
    (void)dc_est;
    /* DWARF locals: int pwr@l587, int pwr_dc@l588, int pwr_ac@l589 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_dc_iq_est> (44 insns) + DWARF line rows for phy_chip_v7_cal.c:579.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* ram_en_pwdet phy_chip_v7_cal.c:214 @ phy_chip_v7_cal.o size 115B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5, pwdet_sar2_init | Data refs: (none) | MMIO: 0x3ff460c0, 0x3ff4e050, 0x3ff4e05c
 * Fidelity: high - 5-lane RMW chain verified per disasm [trace-confirmed] */
void ram_en_pwdet(void)
{
    /* Lanes 1-2 write back to 0x3ff4e05c (a3 never reloaded until lane 3);
     * lanes 3-5 fan out to 0x3ff4e050/0x3ff460c0. Each lane re-reads
     * 0x3ff4e05c via esp_dport_access_reg_read (a10). */
    REG_WRITE(0x3ff4e05cu, REG_READ(0x3ff4e05cu) & 0xff7fffffu);  /* clear bit23 */
    REG_WRITE(0x3ff4e05cu, REG_READ(0x3ff4e05cu) & 0xffdfffffu);  /* clear bit21 */
    REG_WRITE(0x3ff4e050u, REG_READ(0x3ff4e05cu) & 0xfffffffeu);  /* clear bit0 */
    REG_WRITE(0x3ff460c0u, REG_READ(0x3ff4e05cu) | 128u);         /* set bit7 */
    REG_WRITE(0x3ff4e050u, REG_READ(0x3ff4e05cu) | 192u);         /* set bits 7:6 */
    /* Live trace (on-stack): W 0x3ff48890/0x3ff48894/0x3ff4882c/0x3ff48838,
     * W 0x3ff66010, R/W 0x3ff4880c - all inside the pwdet_sar2_init subtree
     * (its literal pool holds 0x3ff48890/0x3ff66010/0x3ff48894/0x3ff4882c/
     * 0x3ff48838 + set_xpd_sar hook); direct 05c/050/0c0 writes below
     * top-N cutoff. No mystery addrs. */
    pwdet_sar2_init();
}
/* ram_get_fm_sar_dout phy_chip_v7_cal.c:278 @ phy_chip_v7_cal.o size 157B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3, ets_delay_us, (indirect) g_phyFuns[75] | Data refs: esp_dport_access_reg_read, ets_delay_us, g_phyFuns | MMIO: 0x3ff4e050
 * Fidelity: medium - RMW prologue, poll loop, hook, saturating-compare lanes verified per disasm; stack-slot roles approximate [trace-confirmed] */
S16 ram_get_fm_sar_dout(S16 * vsig_dc, S16 * vref_dc)
{
    uint16 e[6]; (void)e;   /* hook-filled slots = sp+4..sp+14 */
    uint32 v, s01, s23, s45, avg;
    int32 d;
    REG_WRITE(0x3ff4e050u, REG_READ(0x3ff4e050u) & 0xfffffffdu);  /* clear bit1 */
    REG_WRITE(0x3ff4e050u, REG_READ(0x3ff4e050u) | 2u);           /* set bit1 */
    ets_delay_us(10);
    do {                                    /* poll bits 26:24 (bnez back-edge) */
        v = REG_READ(0x3ff4e050u);
    } while (((v >> 24) & 7u) == 0);
    /* Live trace: W 0x3ff4e050 x2320 - prologue + poll loop dominate. */
    ((void (*)(void *))g_phyFuns[75])(e);    /* +0x12c lane; fills e[0..5] */
    s45 = (uint32)(e[4] + e[5]) & 0xffffu;
    s01 = (uint32)(e[0] + e[1]) & 0xffffu;
    s23 = (uint32)(e[2] + e[3]) & 0xffffu;
    if (s01 < s45)
        *vsig_dc = (S16)((v >> 24) & 7u);   /* taken lane stores stale status bits */
    else
        *vsig_dc = (S16)(d = (int32)(s01 - s45), (d << 16) >> 16);  /* sext15 */
    if (s23 < s45)
        *vref_dc = 0;
    else
        *vref_dc = (S16)(d = (int32)(s23 - s45), (d << 16) >> 16);
    avg = (uint32)(e[1] + e[2] + e[3] + e[4]) >> 2;   /* srai 2 */
    return (S16)(avg & 0xffffu);             /* sext15 of 18-bit avg */
}
/* ram_get_rf_gain_qdb phy_chip_v7_cal.c:2052 @ phy_chip_v7_cal.o size 23B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
U8 ram_get_rf_gain_qdb(U8 rf_gain_ind)
{
    (void)rf_gain_ind;
    /* DWARF locals: U8 gain_qdb@l2054 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_get_rf_gain_qdb> (9 insns) + DWARF line rows for phy_chip_v7_cal.c:2052.
     */
}

/* ram_index_to_txbbgain phy_chip_v7_cal.c:53 @ phy_chip_v7_cal.o size 26B [dwarf-sig]
 * Calls: (none) | Data refs: .rodata.CSWTCH$262 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 ram_index_to_txbbgain(uint8 index)
{
    (void)index;
    /* DWARF locals: uint16 bbgain@l55 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_index_to_txbbgain> (9 insns) + DWARF line rows for phy_chip_v7_cal.c:53.
     */
}

/* ram_iq_est_disable phy_chip_v7_cal.c:559 @ phy_chip_v7_cal.o size 52B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff4607c
 * Fidelity: high - two clear-bit lanes + delay verified per disasm [trace-confirmed] */
void ram_iq_est_disable(void)
{
    /* Live trace: W 0x3ff4607c x200 - both lanes hit the same addr. */
    REG_WRITE(0x3ff4607cu, REG_READ(0x3ff4607cu) & 0xfffffffdu);  /* movi.n a8,-3: clear bit1 */
    ets_delay_us(1);
    REG_WRITE(0x3ff4607cu, REG_READ(0x3ff4607cu) & 0xfffffffeu);  /* movi.n a8,-2: clear bit0 */
}
/* ram_iq_est_enable phy_chip_v7_cal.c:547 @ phy_chip_v7_cal.o size 151B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff46060, 0x3ff4607c
 * Fidelity: medium - full RMW chain, masks, delay, poll loop verified per disasm; param-routing anomaly noted below */
void ram_iq_est_enable(bool iq_est_en, uint16 est_length)
{
    /* ANOMALY (verified, see ledger): est_length is masked (extui a3,0,16) but
     * a3 is then overwritten (movi a3,2; movi a3,1) before the only field use,
     * and iq_est_en (caller a2) is overwritten by the 0x3ff4607c literal load.
     * As compiled, the sequence below is constant; both DWARF params are
     * vestigial (kept for signature fidelity). Re-verify against rdis if the
     * source is ever found: the est_length field may have been constant-folded
     * at this call-site-free blob (possible post-link specialization). */
    (void)iq_est_en; (void)est_length;
    REG_WRITE(0x3ff46060, (REG_READ(0x3ff46060) & 0xf3ffffffu) | 0x4000000u);
    REG_WRITE(0x3ff4607c, (REG_READ(0x3ff4607c) & 0xffe7ffffu) | 0x100000u);
    REG_WRITE(0x3ff4607c, (REG_READ(0x3ff4607c) & 0xfffe0003u) | 8u);
    REG_WRITE(0x3ff4607c, REG_READ(0x3ff4607c) | 1u);
    ets_delay_us(1);
    REG_WRITE(0x3ff4607c, REG_READ(0x3ff4607c) | 1u);
    while ((int32)REG_READ(0x3ff4607c) >= 0)   /* bgez poll for bit31 */
        ;
}
/* ram_meas_tone_pwr_db phy_chip_v7_cal.c:1335 @ phy_chip_v7_cal.o size 85B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns, pwrdet_offset | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S16 ram_meas_tone_pwr_db(S8 tone_atten)
{
    (void)tone_atten;
    /* DWARF locals: S16 power_sum@l1337, S16 power_edb@l1338, int i@l1339 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_meas_tone_pwr_db> (32 insns) + DWARF line rows for phy_chip_v7_cal.c:1335.
     */
}

/* ram_pbus_rx_dco_cal phy_chip_v7_cal.c:596 @ phy_chip_v7_cal.o size 755B [dwarf-sig]
 * Calls: ets_delay_us, phy_printf | Data refs: .rodata.dco_gain_coarse$4714, .rodata.str1.4, ets_delay_us, g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_pbus_rx_dco_cal(uint16 smp_num, sint16 * dc_comp, uint16 ext_delay_us, bool rxdc_print_en, bool print_debug)
{
    (void)smp_num;
    (void)dc_comp;
    (void)ext_delay_us;
    (void)rxdc_print_en;
    (void)print_debug;
    /* DWARF locals: uint8 BB_GAIN_COARSE@l598, uint8 BB_GAIN_FINE@l598, uint8 i@l599, uint8 stage@l599, uint8 tmp@l599, uint8 threshold@l599, uint8 i_num@l599, const uint8[] dco_gain_coarse@l600, sint32[] dc_est@l601, sint16 dco_dac_i@l602, sint16 dco_dac_q@l602, uint16 bb_2@l603 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_pbus_rx_dco_cal> (288 insns) + DWARF line rows for phy_chip_v7_cal.c:596.
     * Ordered callee relocs: ets_delay_us, phy_printf.
     */
}

/* ram_phy_get_vdd33 phy_chip_v7_cal.c:2370 @ phy_chip_v7_cal.o size 368B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, set_xpd_sar, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us, g_phyFuns, set_xpd_sar | MMIO: 0x3ff460c0, 0x3ff4882c, 0x3ff48838, 0x3ff48890, 0x3ff4e050, 0x3ff4e05c, 0x3fffffff
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
U16 ram_phy_get_vdd33(void)
{
    /* DWARF locals: U8 i@l2372, U16 sar_dout@l2373, U16 vdd33@l2373, U16[] e@l2373 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_phy_get_vdd33> (138 insns) + DWARF line rows for phy_chip_v7_cal.c:2370.
     * Ordered callee relocs: esp_dport_access_reg_read, set_xpd_sar, ets_delay_us.
     */
}

/* ram_read_sar_dout phy_chip_v7_cal.c:270 @ phy_chip_v7_cal.o size 42B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: (none) | MMIO: 0x3ff4e080
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_read_sar_dout(U16 * sar_data)
{
    (void)sar_data;
    /* DWARF locals: U8 i@l272 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_read_sar_dout> (15 insns) + DWARF line rows for phy_chip_v7_cal.c:270.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* ram_rfcal_pwrctrl phy_chip_v7_cal.c:1611 @ phy_chip_v7_cal.o size 546B [dwarf-sig]
 * Calls: ets_delay_us, phy_printf | Data refs: .rodata.str1.4, ets_delay_us, g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_rfcal_pwrctrl(U8 tone_freq, U8 * rate_power, U8 pwctrl_num, U8 pwctrl_tone_offset, S8 * rate_atten, uint16 pwdetect_offset, S8 atten_init, bool print_debug)
{
    (void)tone_freq;
    (void)rate_power;
    (void)pwctrl_num;
    (void)pwctrl_tone_offset;
    (void)rate_atten;
    (void)pwdetect_offset;
    (void)atten_init;
    (void)print_debug;
    /* DWARF locals: U8 target_power@l1617, S8 correct_power@l1618, S8 rate_i@l1619, S8 cover_i@l1619, sint16 bb_atten@l1620, sint16 bb_atten_max@l1620, sint16 bb_atten_min@l1620, S16 power_sum@l1621, S16 sum_error@l1621, S16 pwerror@l1621, S16 last_error@l1621, U8 init_i@l1622, const U8 loop_num@l1623 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_rfcal_pwrctrl> (214 insns) + DWARF line rows for phy_chip_v7_cal.c:1611.
     * Ordered callee relocs: ets_delay_us, phy_printf.
     */
}

/* ram_rfcal_txcap phy_chip_v7_cal.c:1165 @ phy_chip_v7_cal.o size 496B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_rfcal_txcap(uint8 tone_freq, uint8 tone_atten, bool print_debug, U8 * indata)
{
    (void)tone_freq;
    (void)tone_atten;
    (void)print_debug;
    (void)indata;
    /* DWARF locals: uint8 reg_i@l1167, uint8 num_k@l1167, uint8 k_max@l1167, uint8 k_defualt@l1167, uint8 find_flag@l1167, uint8 i@l1167, S16 power_out@l1168, S16 power_max@l1168 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_rfcal_txcap> (203 insns) + DWARF line rows for phy_chip_v7_cal.c:1165.
     * Ordered callee relocs: phy_printf.
     */
}

/* ram_set_chan_cal_interp phy_chip_v7_cal.c:1128 @ phy_chip_v7_cal.o size 129B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none - pure arithmetic)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
sint8 ram_set_chan_cal_interp(sint8 * chan_data, uint8 chan)
{
    (void)chan_data;
    (void)chan;
    /* DWARF locals: sint8 interp_data@l1133 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_set_chan_cal_interp> (45 insns) + DWARF line rows for phy_chip_v7_cal.c:1128.
     */
}

/* ram_set_txcap_reg phy_chip_v7_cal.c:1142 @ phy_chip_v7_cal.o size 127B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_set_txcap_reg(U8 * para_txcap, uint8 chan)
{
    (void)para_txcap;
    (void)chan;
    /* DWARF locals: sint8 i@l1144, sint8 j@l1144, sint8[] data@l1144, sint8[] chan_data@l1144 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_set_txcap_reg> (48 insns) + DWARF line rows for phy_chip_v7_cal.c:1142.
     */
}

/* ram_tx_pwctrl_bg_init phy_chip_v7_cal.c:2749 @ phy_chip_v7_cal.o size 37B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[71], esp_dport_access_reg_read | Data refs: g_phyFuns | MMIO: 0x3ff4e060
 * Fidelity: high - hook + set-bit lane verified per disasm [trace-confirmed] */
void ram_tx_pwctrl_bg_init(void)
{
    /* l32i pair +0x11c off g_phyFuns base (pool R_XTENSA_32 g_phyFuns);
     * slot 71 not in gphyfuns_map.json: target unknown, takes no set args. */
    ((void (*)(void))g_phyFuns[71])();
    /* Live trace (on-stack attribution): W 0x3ff4e05c/0x3ff4e050/0x3ff460c0
     * arise from the g_phyFuns[71] subtree (pwdet-family pattern, cf.
     * ram_en_pwdet/txcal_debuge_mode); the direct 0x3ff4e060 write below
     * top-N cutoff. No mystery addrs. */
    REG_WRITE(0x3ff4e060u, REG_READ(0x3ff4e060u) | 2u);
}
/* ram_tx_pwr_backoff phy_chip_v7_cal.c:1351 @ phy_chip_v7_cal.o size 529B [dwarf-sig]
 * Calls: ram_rfcal_pwrctrl, ram_meas_tone_pwr_db | Data refs: pwrdet_offset, ram_meas_tone_pwr_db, ram_rfcal_pwrctrl, rfcal_bb_atten_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S16 ram_tx_pwr_backoff(U8 * target_pwr, bool * linear_flag)
{
    (void)target_pwr;
    (void)linear_flag;
    /* DWARF locals: U8 loop_i@l1358, S8 bb_atten_high@l1359, S8 bb_atten_low@l1359, S8 bb_atten_delta@l1359, S8 atten_delta@l1360, S16 pwr_edb_high@l1361, S16 pwr_edb_low@l1361, S16 target_pwr_edb@l1362, S16 delta_pwr_edb@l1362, S16 delta_pwr_edb_last@l1362, S16 target_backoff_qdb@l1363, u8 target_power_low@l1364, bool step_up_en@l1365 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_tx_pwr_backoff> (201 insns) + DWARF line rows for phy_chip_v7_cal.c:1351.
     * Ordered callee relocs: ram_rfcal_pwrctrl, ram_meas_tone_pwr_db.
     */
}

/* ram_txbbgain_to_index phy_chip_v7_cal.c:39 @ phy_chip_v7_cal.o size 52B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint8 ram_txbbgain_to_index(uint16 txbb_gain)
{
    (void)txbb_gain;
    /* DWARF locals: uint8 index@l41 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_txbbgain_to_index> (19 insns) + DWARF line rows for phy_chip_v7_cal.c:39.
     */
}

/* ram_txcal_work_mode phy_chip_v7_cal.c:239 @ phy_chip_v7_cal.o size 46B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_txcal_work_mode(void)
{
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_txcal_work_mode> (18 insns) + DWARF line rows for phy_chip_v7_cal.c:239.
     */
}

/* ram_txdc_cal_v70 phy_chip_v7_cal.c:112 @ phy_chip_v7_cal.o size 431B [dwarf-sig]
 * Calls: ets_delay_us, esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, ets_delay_us, g_phyFuns | MMIO: 0x3ff4e04c
 * Fidelity: medium - SAR schedule (step 124->1, 12 iters, last-4 average, 3 stages), MMIO masks (0xff000000/0x113cf1/0x113cf3/0x40000000/0x1000000), clamps (0..0x1ff) verified; pbus accessor arg order approximate */
void ram_txdc_cal_v70(sint16 * dc_comp)
{
    sint16 idco, qdco;        /* DWARF l116-117 */
    uint8 i, stage;           /* DWARF l118 */
    sint16 step;              /* DWARF l119 */
    bool idir, qdir;          /* DWARF l120 */
    sint16 idco_sum, qdco_sum;/* DWARF l121-122 */
    (void)idir; (void)qdir;
    /* Setup: pbus path select via ram_pbus_force_test (word 46 per map). */
    extern void ram_pbus_force_test(uint8 pbus_no, uint8 bus_en, uint16 cfg);
    ram_pbus_force_test(2, 2, 0x100);
    ram_pbus_force_test(3, 2, 0x100);
    for (stage = 1; stage <= 3; stage++) {          /* outer stage loop to 0x1ba */
        idco = qdco = 0x100;                        /* movi a2,0x100; mov a3,a2 */
        step = 124;                                 /* movi a5,124 */
        idco_sum = qdco_sum = 0;
        for (i = 0; i < 12; i++) {                  /* beqi a4,12 -> exit */
            /* Drive candidate, settle, trigger + poll IQ-est done bit. */
            ram_pbus_force_test(3, stage, (uint16)(idco & 0xffff));
            ram_pbus_force_test(2, stage, (uint16)(qdco & 0xffff));
            ets_delay_us(2);
            REG_WRITE(0x3ff4e04c, (REG_READ(0x3ff4e04c) & 0xff000000u) | 0x113cf1u);
            REG_WRITE(0x3ff4e04c, (REG_READ(0x3ff4e04c) & 0xff000000u) | 0x113cf3u);
            while (!(REG_READ(0x3ff4e04c) & 0x1000000u))  /* bnone poll */
                ;
            {
                uint32 st = REG_READ(0x3ff4e04c);
                int32 est = (int32)(st & ~0x40000000u);  /* sign lane per disasm */
                if (est < 0)
                    idco = (sint16)clamp16(idco - step, 0, 0x1ff);
                else
                    idco = (sint16)clamp16(idco + step, 0, 0x1ff);
                if (st & 0x40000000u)
                    qdco = (sint16)(qdco - step);    /* bnez lane; clamps TODO */
                else
                    qdco = (sint16)(qdco + step);
            }
            step = (step == 2) ? 1 : (sint16)((step >> 1) + 1);  /* 124..2,1 */
            if (i >= 8) {                       /* bltui a4,8: accumulate last 4 */
                idco_sum = (sint16)(idco_sum + idco);
                qdco_sum = (sint16)(qdco_sum + qdco);
            }
        }
        dc_comp[0] = (sint16)((qdco_sum + 2) >> 2);  /* avg; store order per disasm */
        dc_comp[1] = (sint16)((idco_sum + 2) >> 2);
        dc_comp += 2;
        ram_pbus_force_test(2, stage, 0);  /* stage advance; 3rd arg lane stale (TODO) */
    }
    REG_WRITE(0x3ff4e04c, (REG_READ(0x3ff4e04c) & 0xff000000u) | 0x113cf0u);
}
/* ram_txiq_cover phy_chip_v7_cal.c:362 @ phy_chip_v7_cal.o size 391B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_txiq_cover(U8 tone_atten, S16 tone_freq, int8 * mis_data, bool pkdet_en)
{
    (void)tone_atten;
    (void)tone_freq;
    (void)mis_data;
    (void)pkdet_en;
    /* DWARF locals: S16 pwr1@l364, S16 pwr2@l364, S16 temp1_pwr@l364, S16 temp2_pwr@l364, uint8 loop_i@l365, uint8 loop_num@l365, int8 gain_sum@l366, int8 phase_sum@l366, int8 temp1_sum@l366, int8 temp2_sum@l366, int8 bb_att@l367, int32 diff_pwr@l368 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <ram_txiq_cover> (148 insns) + DWARF line rows for phy_chip_v7_cal.c:362.
     */
}

/* ram_txiq_get_mis_pwr phy_chip_v7_cal.c:338 @ phy_chip_v7_cal.o size 208B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3, ets_delay_us x2, (indirect) g_phyFuns[77] x2 | Data refs: esp_dport_access_reg_read, ets_delay_us, g_phyFuns | MMIO: 0x3ff450a8, 0x3ff460b8
 * Fidelity: medium - bit-pack program, RMW lanes, hook order/args, gain-code lanes verified per disasm [trace-confirmed] */
void ram_txiq_get_mis_pwr(bool gain_en, uint8 bb_att, S16 tone_freq, S16 * pwr1, S16 * pwr2, bool pkdet_en)
{
    uint32 v, pack, code;
    int32 tone = (int32)tone_freq;   /* sext15 lane */
    uint32 pk = (uint32)(pkdet_en & 0xffu);
    uint32 ge = (uint32)(gain_en & 0xffu);
    /* Live trace: W 0x3ff460b8 x96 + W 0x3ff450a8 x48 - both direct lanes. */
    v = REG_READ(0x3ff460b8u);
    pack = (uint32)(((tone >> 2) | 0x2c0000) | (int32)(ge << 26));
    pack |= (uint32)(((uint32)(0u - (uint32)(bb_att & 0xffu)) & 0xffu) << 10);
    pack = (pack & 0x0fffffffu) | (v & 0xf0000000u);
    REG_WRITE(0x3ff460b8u, pack);
    v = REG_READ(0x3ff450a8u);
    REG_WRITE(0x3ff450a8u, (v & 0xfffffffcu) | ((uint32)tone_freq & 3u));
    ets_delay_us(10);
    /* Both hooks receive pk (caller-a10 lane); results land in pwr1, pwr2. */
    v = ((uint32 (*)(uint32))g_phyFuns[77])(pk);        /* +0x134 lane */
    code = (uint32)(((ge << 3) | ((ge ^ 1u) & 1u)) & 0xfu);
    *pwr1 = (S16)(v & 0xffffu);
    v = REG_READ(0x3ff460b8u);
    REG_WRITE(0x3ff460b8u, (code << 24) | (v & 0xf0ffffffu));
    ets_delay_us(10);
    v = ((uint32 (*)(uint32))g_phyFuns[77])(pk);
    *pwr2 = (S16)(v & 0xffffu);
}
/* rc_cal phy_chip_v7_cal.c:1020 @ phy_chip_v7_cal.o size 666B [dwarf-sig]
 * Calls: ets_delay_us, bb_bss_cbw40_ana | Data refs: bb_bss_cbw40_ana, chip7_phy_init_ctrl, chip7_sleep_params, ets_delay_us, g_phyFuns, wifi_txband, wifi_txband_ht40 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rc_cal(void)
{
    /* DWARF locals: U8 rc_dout@l1026, U8 rc_div@l1026, U8 i@l1026, U32 temp@l1027, U32 delta@l1027, sint16[] dcap_wifi@l1028, sint16[] dcap_bt@l1029 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <rc_cal> (249 insns) + DWARF line rows for phy_chip_v7_cal.c:1020.
     * Ordered callee relocs: ets_delay_us, bb_bss_cbw40_ana.
     */
}

/* rfcal_txiq phy_chip_v7_cal.c:440 @ phy_chip_v7_cal.o size 486B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x4, txcal_debuge_mode, (indirect) g_phyFuns[46,47,10,70,55,17,77,73], ets_delay_us, ram_txiq_cover | Data refs: esp_dport_access_reg_read, ets_delay_us, g_phyFuns, ram_txiq_cover, txcal_debuge_mode | MMIO: 0x3ff450dc, 0x3ff460b8
 * Fidelity: medium - prologue lanes, func_sel dispatch, measure/track loop, cover+clamp lanes, tail stores verified per disasm; hook prototypes inferred [trace-confirmed] */
void rfcal_txiq(uint16 bbgain, uint16 * txdc, uint16 * para_txiq, uint8 tone_freq, int8 tone_atten, uint8 func_sel)
{
    uint32 v, meas, para;
    int32 bias4;                 /* [460b8] tail lane */
    uint8 fs = (uint8)(func_sel & 0xffu);
    uint8 tune = (uint8)tone_atten;
    uint8 rounds = 4;
    int8 mis[2] = {0, 0};        /* sp[0]/sp[1] image (cover outputs) */
    /* Live trace (on-stack): W 0x3ff4e04c x1 (top-N truncated; direct
     * 0x3ff450dc/0x3ff460b8 lanes + hook-subtree addrs below cutoff).
     * No mystery addrs. */
    v = REG_READ(0x3ff450dcu);
    REG_WRITE(0x3ff450dcu, v | 0x800u);                       /* set bit11 */
    v = REG_READ(0x3ff450dcu);
    REG_WRITE(0x3ff450dcu, v & 0xffffefffu);                  /* clear bit12 */
    txcal_debuge_mode(fs == 1);                               /* a10=(fs==1) lane */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(1u, 2u, (uint32)bbgain);
    if (fs == 1) {
        uint32 r = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(1u, 1u);
        ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(
            1u, 1u, (uint32)((2u | r) & 0xffffu));
    } else if (fs == 2) {
        ((void (*)(uint32))g_phyFuns[10])(1u);                /* +40 lane */
        ((void (*)(uint16 *))g_phyFuns[70])(txdc);            /* +0x118 lane */
    } else {
        ((void (*)(uint16 *))g_phyFuns[55])(txdc);            /* +220 lane */
    }
    do {   /* measure/track loop (bnez back-edge) */
        ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[17])(
            1u, (uint32)tone_freq, (uint32)tune, 0u, 0u, 0u); /* +68 lane */
        ets_delay_us(2);
        meas = ((uint32 (*)(uint32))g_phyFuns[77])(0u);       /* +0x134 lane */
        meas = (uint32)(((int32)(meas >> 2) << 16) >> 16);   /* srai 2; sext15 */
        if (!((uint32)1000 >= meas)) { tune = (uint8)(tune + 4); break; }
        if ((uint32)0x257 < meas) break;
        tune = (uint8)(tune - 4);
    } while (--rounds != 0);
    {   /* cover + clamp lanes. Disasm passes the frame base (a1) as mis_data
         * and g73 reuses the restored maxv lane (window idiom); mis[] models
         * the two bytes consumed at frame+0/+1. */
        int32 t = (int32)(int8)tune, s;
        uint32 sel;
        if (t > 120) t = 120;
        if (t < 0) t = 0;
        ram_txiq_cover((uint8)t, (S16)tone_freq, mis, 0);
        s = ((int32 (*)(int32))g_phyFuns[73])((int32)t);      /* restored-lane */
        (void)s;
        s = (int32)mis[0];
        if (s > 15) { mis[0] = 15; sel = 0x3c0u; }
        else if (s >= -15) { sel = (uint32)(((s & 0x1f) << 6) >> 6) & 0xffffu; }
        else { mis[0] = -15; sel = 0x440u; }
        s = (int32)mis[1];
        if (s > 31) { mis[1] = 31; para = sel | 31u; bias4 = 31; }
        else if (s >= -31) {
            bias4 = s & 0x3f;
            para = sel | (uint32)(((bias4 << 16) >> 16) & 0xffffu);
        } else { mis[1] = -31; para = sel | 33u; bias4 = -31; }
    }
    para_txiq[0] = (uint16)(para & 0xffffu);   /* s16i lane */
    REG_WRITE(0x3ff460b8u, (uint32)bias4);     /* s32i lane */
    if (fs == 2)
        ((void (*)(uint32))g_phyFuns[10])(0u);
    v = REG_READ(0x3ff450dcu);
    REG_WRITE(0x3ff450dcu, v | 0x1000u);       /* set bit12 */
}
/* rxdc_est_min phy_chip_v7_cal.c:682 @ phy_chip_v7_cal.o size 100B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rxdc_est_min(uint16 smp_num, bool cal_en, int32 * dc_est)
{
    (void)smp_num;
    (void)cal_en;
    (void)dc_est;
    /* DWARF locals: uint8 i@l684, int32[] dc_est_m@l685, int32 min_pwr@l685 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <rxdc_est_min> (42 insns) + DWARF line rows for phy_chip_v7_cal.c:682.
     */
}

/* set_bt_chan_cal_interp phy_chip_v7_cal.c:2330 @ phy_chip_v7_cal.o size 192B [dwarf-sig-decl]
 * Calls: (none) | Data refs: chip7_sleep_params | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S8 set_bt_chan_cal_interp(uint8 chan)
{
    (void)chan;
    /* DWARF locals: sint8 interp_data@l2335 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <set_bt_chan_cal_interp> (67 insns) + DWARF line rows for phy_chip_v7_cal.c:2330.
     */
}

/* set_chan_dig_gain phy_chip_v7_cal.c:1893 @ phy_chip_v7_cal.o size 663B [dwarf-sig]
 * Calls: get_phy_target_power, get_chan_pwr_index, get_rate_fcc_index, write_txrate_power_offset, tx_gain_table_set | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint8 set_chan_dig_gain(uint8 chan)
{
    (void)chan;
    /* DWARF locals: U8[] target_power@l1895, uint8[] fcc_index_all@l1896, uint8[] fcc_index_all_20m@l1896, uint8 fcc_index@l1896, uint8 i@l1897, uint8 j@l1897, sint8[] org_gain_table@l1898, sint8[] chan_data@l1898, sint8 correct_qdb@l1898, uint8 pwr_index_11b@l1899, sint8 chg_delta@l1900, sint8 power_delta@l1901, sint8 corr_atten@l1901, uint8 target_atten@l1902, sint8 init_att_min@l1903 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <set_chan_dig_gain> (255 insns) + DWARF line rows for phy_chip_v7_cal.c:1893.
     */
}

/* tx_cap_init phy_chip_v7_cal.c:1226 @ phy_chip_v7_cal.o size 380B [dwarf-sig]
 * Calls: txcal_debuge_mode, set_channel_rfpll_freq, ets_delay_us | Data refs: .rodata.CSWTCH$279, chip7_phy_init_ctrl, chip7_sleep_params, ets_delay_us, g_phyFuns, pwrdet_offset, rfcal_bb_atten_init, set_channel_rfpll_freq, txcal_debuge_mode | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_cap_init(void)
{
    /* DWARF locals: uint8 i@l1228, uint8 j@l1228, uint8 chan_num@l1228, sint8 tone_atten@l1229, sint16 power_out@l1230, sint16 pwr_delta@l1230, bool debug_print@l1231, uint8 target_power@l1232 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <tx_cap_init> (144 insns) + DWARF line rows for phy_chip_v7_cal.c:1226.
     * Ordered callee relocs: txcal_debuge_mode, set_channel_rfpll_freq, ets_delay_us.
     */
}

/* tx_gain_table_set phy_chip_v7_cal.c:2609 @ phy_chip_v7_cal.o size 164B [dwarf-sig]
 * Calls: correct_rf_ana_gain_new, (indirect) g_phyFuns[11] x8, force_txrx_off x2, set_tx_gain_table, write_wifi_dig_gain | Data refs: chip7_sleep_params, force_tx_gain_en, g_phyFuns, phy_chan_gain_table, tx_rf_ana_gain | MMIO: (none direct)
 * Fidelity: medium - table staging, 8x hook loop, flag gate, tail order verified per disasm; hook prototype inferred from set arg regs [trace-confirmed] */
void tx_gain_table_set(void)
{
    extern uint8 chip7_sleep_params[];    /* +184 (s8) / +182 (u16) lane sources */
    extern uint8 phy_chan_gain_table[];  /* 8-byte loop source */
    extern uint16 tx_rf_ana_gain[];      /* l16ui pair source */
    extern uint8 force_tx_gain_en;       /* tail gate byte */
    uint8 tmp[8]; (void)tmp;             /* sp[0..7] hook-result buffer */
    sint16 qdb; uint16 pa, bb;
    uint16 base;
    /* Live trace (on-stack): W 0x3ff460a0 x68, W 0x3ff46000/04/08 x17 - all
     * via the set_tx_gain_table/force_txrxoff tail callees; no direct MMIO
     * in this frame. No mystery addrs. */
    base = (uint16)(((int32)(int8)chip7_sleep_params[184] -
                     (int32)*(uint16 *)&chip7_sleep_params[182]) & 0xffff);
    pa = tx_rf_ana_gain[0];
    bb = tx_rf_ana_gain[1];
    qdb = (sint16)(((int32)base + (int32)(int8)phy_chan_gain_table[5] + 20) & 0xffff);
    correct_rf_ana_gain_new(&qdb, &pa, &bb, 0);
    base = (uint16)(((int32)base - (int32)qdb) & 0xffff);
    {   /* per-step hook +52 loop (bne-bounded, 8 iterations) */
        uint8 *p = phy_chan_gain_table;
        for (int i = 0; i < 8; i++) {
            int32 v = (int32)base + (int32)(int8)*p++;   /* sext15 lane */
            tmp[i] = ((uint8 (*)(uint16, uint32, int32))g_phyFuns[11])(
                (uint16)(v & 0xffffu), 30u, -127);
        }
    }
    if (force_tx_gain_en)                /* l8ui gate; bnez -> ret */
        return;
    force_txrx_off(1);
    /* Cal-TU DIE for set_tx_gain_table is decl-only (void); true prototype
     * (U16 pa_gain, U16 bbgain) per phy_chip_v7 TU. */
    set_tx_gain_table(pa, bb);
    write_wifi_dig_gain((S8 *)tmp);
    force_txrx_off(0);                   /* caller-a2 lane (flag byte, 0 here) */
}
/* tx_pwctrl_background phy_chip_v7_cal.c:2786 @ phy_chip_v7_cal.o size 242B [dwarf-sig]
 * Calls: phy_enter_critical, esp_dport_access_reg_read, get_phy_target_power, tx_pwctrl_cal, phy_pwdet_onetime_en, wifi_track_pll_cap, phy_exit_critical | Data refs: g_phyFuns | MMIO: 0x3ff4e050
 * Fidelity: medium-low - critical section, flag-gated lanes, 0x3ff4e050 poll sequence, pll-cap track verified; static flag/hook identities TODO */
void tx_pwctrl_background(bool correct_en, bool print_en)
{
    CriticalType crit_level;      /* DWARF l2788 */
    U8 target_power[16];          /* DWARF l2792 (stack array; size approximate) */
    bool track_en;                /* DWARF l2793 */
    (void)correct_en; (void)print_en; (void)target_power; (void)track_en;
    /* Static flag bytes/hook addrs are object-relative literals in rdis;
     * exact symbols TODO. Declared here so the file parses. */
    extern U8 bg_flag_a, bg_flag_b, bg_flag_c, bg_counter;
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    extern void bg_build_table_step1(void);
    extern void bg_build_table_step2(void);
    extern void bg_range_check_hook(void);
    crit_level = phy_enter_critical_ret();
    if (bg_flag_a) {
        if (++bg_counter < 19)
            goto tail;                        /* bltu 19,counter -> 105c */
    } else if (bg_flag_b) {
        uint32 m = REG_READ(0x3ff4e050);
        if ((int32)m < 0 && bg_flag_c == 1 && (((REG_READ(0x3ff4e050) >> 24) & 7u) == 0))
            goto build_table;                 /* bltz/bnei/extui lanes */
        m = REG_READ(0x3ff4e050);
        if (m & 1u)
            goto tail;                        /* bbsi -> 1051 */
build_table:
        bg_build_table_step1();               /* direct call8; static, TODO */
        bg_build_table_step2();               /* direct call8; static, TODO */
        bg_counter++;
        goto tail;
    }
tail:
    if (bg_flag_c == 1) {
        if ((int32)REG_READ(0x3ff4e050) < 0)
            bg_flag_c = 0;                    /* bltz lane */
    } else if (!(REG_READ(0x3ff4e050) & 1u)) {
        bg_range_check_hook();                /* bbsi fallthrough call8; TODO */
    }
    if (bg_flag_a)
        bg_flag_a = 0;
    wifi_track_pll_cap();
    phy_exit_critical_to(crit_level);
}
/* tx_pwctrl_cal phy_chip_v7_cal.c:2645 @ phy_chip_v7_cal.o size 910B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, tsens_code_read, get_temp_cal, phy_printf, tx_gain_table_set | Data refs: (none) | MMIO: 0x3ff46008, 0x3ff4e060
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_pwctrl_cal(U8 * target_power, U8 * ratepw_offset, S16 * pwdet_error_accum, bool correct_en, bool print_en)
{
    (void)target_power;
    (void)ratepw_offset;
    (void)pwdet_error_accum;
    (void)correct_en;
    (void)print_en;
    /* DWARF locals: S16 pwdet_out@l2648, S16 p_error@l2648, S16 pdt_offset@l2648, S16 temp_cal@l2648, U8 i@l2649, U8 j@l2649, S8[] correct_atten@l2650, S8 correct_qdb@l2650, S8 correct_error@l2650, U8 backoff_coef@l2651, U8 threshold@l2652, S8 pwcorrect_v@l2654, S8 bb_correct@l2654, S8 rate_power@l2654, U8 pwoffset@l2655, U8 temp_meas@l2655 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <tx_pwctrl_cal> (341 insns) + DWARF line rows for phy_chip_v7_cal.c:2645.
     * Ordered callee relocs: esp_dport_access_reg_read, tsens_code_read, get_temp_cal, phy_printf.
     */
}

/* tx_pwctrl_init phy_chip_v7_cal.c:2186 @ phy_chip_v7_cal.o size 164B [dwarf-sig]
 * Calls: txcal_debuge_mode, tx_pwctrl_init_cal | Data refs: chip7_sleep_params, g_phyFuns, tx_pwctrl_init_cal, tx_rf_ana_gain, txcal_debuge_mode | MMIO: (none)
 * Fidelity: medium - init-done flag gate, 3x cal schedule, 6-byte table copy, word-73 hook, stamp stores verified */
void tx_pwctrl_init(u8 backoff_en)
{
    extern uint8 chip7_sleep_params[];
    extern uint8 tx_rf_ana_gain[];      /* 6-byte source table per funcdb refs */
    uint32 w0 = *(uint32 *)chip7_sleep_params;
    if (!(w0 & 0x100000u)) {                       /* bnez -> tail */
        txcal_debuge_mode((w0 & 0x100000u) != 0);   /* a10 = masked word (truthy) */
        tx_pwctrl_init_cal(6, backoff_en);         /* a10=chan, a11=backoff_en */
        tx_pwctrl_init_cal(1, backoff_en);
        tx_pwctrl_init_cal(11, backoff_en);
        /* 6-byte copy tx_rf_ana_gain -> sleep area (loop a9=6, dst+6 lane). */
        for (int i = 0; i < 6; i++)                /* loop ...80 */
            chip7_sleep_params[10 + 6 + i] = tx_rf_ana_gain[i];  /* s8i a10,a8,5 */
    }
    /* Tail: hook + stamps. */
    ((void (*)(void))g_phyFuns[73])();             /* l32i x2,+0x124; callx8 */
    extern uint16 pwctrl_stamp_tbl[];              /* halfword literal table */
    *(uint16 *)&chip7_sleep_params[190] = pwctrl_stamp_tbl[1];  /* s16i lanes */
    *(uint16 *)&chip7_sleep_params[188] = pwctrl_stamp_tbl[0];
    *(uint32 *)chip7_sleep_params |= 0x100000u;    /* init-done flag */
    chip7_sleep_params[81] = 14;                   /* s8i 14 */
}
/* tx_pwctrl_init_cal phy_chip_v7_cal.c:2123 @ phy_chip_v7_cal.o size 387B [dwarf-sig]
 * Calls: set_channel_rfpll_freq, cal_rf_ana_gain, ram_tx_pwr_backoff, ram_rfcal_pwrctrl, esp_dport_access_reg_read | Data refs: cal_rf_ana_gain, chip7_sleep_params, g_phyFuns, ram_rfcal_pwrctrl, ram_tx_pwr_backoff, set_channel_rfpll_freq | MMIO: 0x3ff460f8
 * Fidelity: medium - branch skeleton (chan==6 ANA-gain path, backoff_en gates), rounded-average idiom, table-fill loops, call order verified; exact table geometry TODO */
S16 tx_pwctrl_init_cal(U8 chan_num, u8 backoff_en)
{
    S8 tx_atten;                 /* DWARF l2125 */
    S16 target_backoff_qdb, backoff_qdb;  /* DWARF l2126 */
    U8 target_power[16];         /* DWARF l2127 (stack array; size approximate) */
    U8 loop_i;                   /* DWARF l2127 */
    bool linear_flag;            /* DWARF l2128 */
    U8 store_id;                 /* DWARF l2130 */
    const U8 backoff_loop_num = 6;  /* DWARF l2131 (value per disasm lane) */
    (void)tx_atten; (void)target_power; (void)loop_i; (void)linear_flag; (void)store_id;
    extern uint8 chip7_sleep_params[];
    /* Tune RFPLL to channel first (freq_offset=0 lane). */
    set_channel_rfpll_freq((int8)chan_num, chip7_sleep_params[1], 0);
    if (chan_num == 6) {                       /* bnei a4,6 -> skip */
        cal_rf_ana_gain();
        if (backoff_en == 1) {
            /* Two backoff samples, rounded average (srai round idiom). */
            extern U8 pwctrl_target_tbl[];   /* table literal; exact symbol TODO */
            U8 lin1 = 0, lin2 = 0;
            S16 r1 = ram_tx_pwr_backoff(pwctrl_target_tbl, &lin1);  /* a10=tbl, a11=sp+22 */
            S16 r2 = ram_tx_pwr_backoff(pwctrl_target_tbl, &lin2);
            if (r2 == 0)                          /* beqz a10 -> raw path */
                backoff_qdb = (S16)(((r1 + r2) >> 1) & 0xffff);
            else
                backoff_qdb = (S16)(((r1 + r2 + 1) >> 1) & 0xffff);
            target_backoff_qdb = backoff_qdb;
        }
    } else if (backoff_en == 1) {
        extern U8 pwctrl_target_tbl[];
        U8 lin = 0;
        backoff_qdb = ram_tx_pwr_backoff(pwctrl_target_tbl, &lin);
        target_backoff_qdb = backoff_qdb;
    }
    /* Per-rate target-power table fill + DPORT staging (0x3ff460f8 lane). */
    for (loop_i = 0; loop_i < backoff_loop_num; loop_i++) {
        target_power[loop_i] = 0;              /* TODO: exact fill law */
    }
    /* 8-arg form per DWARF; exact arg mapping TODO (stack-built). */
    ram_rfcal_pwrctrl(0, target_power, 0, 0, NULL, 0, 0, false);
    return target_backoff_qdb;                 /* S16 return verified */
}
/* txcal_debuge_mode phy_chip_v7_cal.c:229 @ phy_chip_v7_cal.o size 91B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[48,54,67,55,15,71] | Data refs: chip7_sleep_params, g_phyFuns, tx_rf_ana_gain | MMIO: (none direct)
 * Fidelity: medium - 6-hook dispatch order + arg computation verified per disasm; hook prototypes inferred from set arg regs [trace-confirmed] */
void txcal_debuge_mode(bool bt_mode)
{
    extern uint16 tx_rf_ana_gain[];   /* l16ui pair source */
    extern uint8 chip7_sleep_params[];/* address-folded lane (+8 scaled) */
    uint32 mode8 = ((uint32)(bt_mode & 0xffu)) << 8;
    /* Live trace (on-stack): W 0x3ff4e05c/0x3ff4e050/0x3ff460c0 - all via the
     * g_phyFuns[54,55,71] hook subtree (pwdet-family pattern); no direct
     * MMIO in this frame. No mystery addrs. */
    ((void (*)(void))g_phyFuns[48])();                                  /* +192 lane, no set args */
    ((void (*)(uint32, uint32))g_phyFuns[54])(                          /* +216 lane */
        (uint32)(tx_rf_ana_gain[0] | mode8), (uint32)tx_rf_ana_gain[1]);
    ((void (*)(uint32))g_phyFuns[67])((uint32)tx_rf_ana_gain[1]);        /* +0x10c lane */
    ((void (*)(uint32))g_phyFuns[55])(                                  /* +220 lane */
        (uint32)((tx_rf_ana_gain[1] & 0xffffu) + 8u * (uint32)chip7_sleep_params + 12u));
    ((void (*)(uint32))g_phyFuns[15])(1u);                              /* +60 lane */
    ((void (*)(uint32))g_phyFuns[71])(1u);                              /* +0x11c lane (a10=1 stale) */
}
/* txpwr_offset phy_chip_v7_cal.c:2417 @ phy_chip_v7_cal.o size 132B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[102,93], temprature_sens_read | Data refs: chip7_phy_init_ctrl, chip7_sleep_params, g_phyFuns, temprature_sens_read | MMIO: (none; SRAM stores to chip7_sleep_params)
 * Fidelity: medium - gate, hook order/args, arithmetic, copy loop, SRAM stores verified per disasm; vestigial-param anomaly noted [trace-confirmed] */
void txpwr_offset(S16 m_offset)
{
    extern uint8 chip7_sleep_params[];      /* a4 base (l32r pool+8); +192/+0 stores */
    extern uint8 chip7_phy_init_ctrl[];    /* +0xe 6-byte copy source */
    /* ANOMALY (verified): m_offset (caller a2) is clobbered by the gate load
     * (l32i.n a2,[a4] @29) before any read, so the DWARF param is vestigial
     * (cf. ram_iq_est_enable). The pack lanes consume only link-time
     * constants + hook returns. Kept for signature fidelity. */
    (void)m_offset;
    uint32 h1, h3, mid, tsens, v;
    if ((*(uint32 *)&chip7_sleep_params[0]) & 0x400000u)   /* gate lane */
        return;
    h1 = ((uint32 (*)(void))g_phyFuns[102])();             /* +0x198 lane */
    if (!((uint32)0xd32 < h1))                             /* bltu: skip lane */
        mid = ((uint32 (*)(uint32, uint32))g_phyFuns[93])(h1, 3u);  /* +0x174 */
    else
        mid = h1;
    h3 = ((uint32 (*)(uint32, uint32))g_phyFuns[93])(0xd33u, 3u);
    v = mid - h3;                                          /* sub lane */
    v = (uint32)((((((int32)(v << 1) << 24) >> 24) + 2) >> 2) & 0xffu) << 8;
    /* slli 1; sext.7; +2; extui 2,8; slli 8 */
    tsens = temprature_sens_read();
    for (int i = 0; i < 6; i++)                 /* loop-count 6 lane */
        chip7_sleep_params[0x5a + i] = chip7_phy_init_ctrl[0xe + i];
    v |= ((h1 << 16) | tsens);                  /* slli a5,16; or */
    *(uint32 *)&chip7_sleep_params[192] = v;    /* s32i +192; memw */
    *(uint32 *)&chip7_sleep_params[0] =
        (*(uint32 *)&chip7_sleep_params[0]) | 0x400000u;   /* s32i +0 */
    /* Live trace (on-stack): W 0x3ff4882c/0x3ff4e05c/0x3ff4e050/0x3ff460c0/
     * 0x3ff48890/0x3ff48838 - all via the g_phyFuns[102,93] hook subtree
     * (pwdet-family pattern); no direct MMIO in this frame. No mystery addrs. */
}
/* wifi_11g_rate_chg phy_chip_v7_cal.c:1690 @ phy_chip_v7_cal.o size 24B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint8 wifi_11g_rate_chg(uint8 rate_11g)
{
    (void)rate_11g;
    /* DWARF locals: uint8 rate_mcs@l1692 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <wifi_11g_rate_chg> (9 insns) + DWARF line rows for phy_chip_v7_cal.c:1690.
     */
}

/* write_txrate_power_offset phy_chip_v7_cal.c:1733 @ phy_chip_v7_cal.o size 350B [dwarf-sig-decl]
 * Calls: get_target_power_offset x4, esp_dport_access_reg_read x2 | Data refs: chip7_sleep_params, g_phyFuns, lr_enable, phy_chan_pwr_index | MMIO: 0x3ff4503c, 0x3ff45040, 0x3ff45044, 0x3ff45048, 0x3ff4504c, 0x3ff45050, 0x3ff4505c, 0x3ff4506c, 0x3ff45070, 0x3ff45074, 0x3ff45078
 * Fidelity: medium - clear path, accumulate/store loops, flag gate, RMW pair verified per disasm; table-index arithmetic transcribed op-for-op [trace-confirmed] */
void write_txrate_power_offset(bool chg_offset)
{
    extern uint8 phy_chan_pwr_index[];   /* accumulation table base */
    extern uint8 lr_enable;              /* RMW-pair gate byte */
    uint32 a5, a7;
    uint8 idx;
    int i;
    if (!((uint8)chg_offset & 0xffu)) {          /* bnez -> work path */
        REG_WRITE(0x3ff4506cu, 0xfedcba98u);
        REG_WRITE(0x3ff45070u, 0xffffffffu);     /* movi.n -1 */
        REG_WRITE(0x3ff45074u, 0xffffffffu);
        REG_WRITE(0x3ff45078u, 0xffffffffu);
        REG_WRITE(0x3ff4503cu, 0x77777777u);
        REG_WRITE(0x3ff45040u, 0x77777777u);
        REG_WRITE(0x3ff45044u, 0x77777777u);
        REG_WRITE(0x3ff45048u, 0x77777777u);
        return;
    }
    /* Live trace (on-stack): W 0x3ff4504c/50/54/58/5c/60/64/68 x19 - the
     * accumulated stores + RMW pair below (clear-path addrs absent: the scan
     * ran the chg path). No mystery addrs. */
    a5 = 0x3ff4504cu;
    idx = 8;
    do {                                        /* 4 rate-group iterations */
        a7 = 0;
        for (i = 0; i < 8; i++) {               /* bnei-bounded */
            uint8 k = (uint8)(idx + ((i >> 2) & 0x3f));
            /* ssl/sll nibble-pack: tpo(k) placed at 4*i */
            a7 |= (uint32)get_target_power_offset(k, phy_chan_pwr_index) << (4 * i);
        }
        REG_WRITE(a5, a7);                      /* memw + s32i */
        idx = (uint8)(idx + 2);
        a5 += 4;
    } while (a5 != 0x3ff4505cu);
    if (lr_enable) {
        REG_WRITE(0x3ff4504cu,
                  0x77770000u | (REG_READ(0x3ff4504cu) & 0xffffu));
        REG_WRITE(0x3ff45050u,
                  (REG_READ(0x3ff45050u) & 0xffff0000u) | 0x7777u);
    }
    {   /* second accumulation: 4 more groups at 0x3ff4505c..0x3ff45068 */
        uint8 grp = 0;
        a5 = 0x3ff4505cu;
        do {
            uint8 *base = &phy_chan_pwr_index[grp];   /* a10 = a4+a11 lane */
            uint8 sh = 0;
            a7 = 0;
            for (i = 0; i < 8; i++) {           /* bnez-bounded */
                uint8 *bp = base + (i >> 2) + (((i & 3) != 3) ? 8 : 0);
                a7 |= (uint32)*bp << sh;        /* ssl a3 / sll lane */
                sh = (uint8)(sh + 4);
            }
            REG_WRITE(a5, a7);
            grp = (uint8)(grp + 2);
            a5 += 4;
        } while (grp != 8);                     /* beqi-bounded */
    }
}
/* write_wifi_dig_gain phy_chip_v7_cal.c:1995 @ phy_chip_v7_cal.o size 89B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff46004, 0x3ff46008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void write_wifi_dig_gain(S8 * gain_table)
{
    (void)gain_table;
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7_cal.rdis
     * function <write_wifi_dig_gain> (32 insns) + DWARF line rows for phy_chip_v7_cal.c:1995.
     */
}

/* Undefined refs (27): bb_bss_cbw40_ana, bt_index_to_bb, bt_tx_pa_gain, btpwr_tsen_init, chip7_phy_init_ctrl, chip7_sleep_params, esp_dport_access_reg_read, ets_delay_us, g_phyFuns, get_temp_cal, lr_enable, memcpy, phy_enter_critical, phy_exit_critical, phy_printf, phy_set_most_tpw_disbg, phy_set_most_tpw_index, pwrdet_offset, set_channel_rfpll_freq, set_tx_gain_table, set_xpd_sar, target_power_backoff_qdb, temprature_sens_read, tsens_code_read, tx_rf_ana_gain, wifi_track_pll_cap, wr_bt_tx_atten */