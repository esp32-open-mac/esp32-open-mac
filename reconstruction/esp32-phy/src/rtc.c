/* Reconstruction of rtc.o (librtc.a)
 * CU: rtc.c | comp_dir: /home/cff/gittree/chip_rtc/chip7.1_rtc/board_code/app_test/pp/rtc
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 27 | funcdb functions: 24
 * Disasm: re/esp32-phy/disasm/librtc/rtc.rdis
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

/* cfg_sdio_volt rtc.c:454 @ rtc.o size 181B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48074
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cfg_sdio_volt(uint8 drefh, uint8 drefm, uint8 drefl)
{
    (void)drefh;
    (void)drefm;
    (void)drefl;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <cfg_sdio_volt> (64 insns) + DWARF line rows for rtc.c:454.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_apbbridge_sel rtc.c:202 @ rtc.o size 36B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_apbbridge_sel(u32 sel)
{
    (void)sel;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_apbbridge_sel> (13 insns) + DWARF line rows for rtc.c:202.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_cmd_ext_wakeup rtc.c:398 @ rtc.o size 166B [dwarf-sig]
 * Calls: rtc_pads_muxsel, rtc_pads_funsel, esp_dport_access_reg_read, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_funie, rtc_pads_pu, rtc_pads_pd | Data refs: esp_dport_access_reg_read, rtc_pads_funie, rtc_pads_funsel, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe, rtc_pads_slpsel | MMIO: 0x3ff48060, 0x3ff4840c, 0x3ff484bc, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_cmd_ext_wakeup(u32 mask, u32 wakeup_sel)
{
    (void)mask;
    (void)wakeup_sel;
    /* DWARF locals: u32 i@l399, u32 filter@l400 */
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_cmd_ext_wakeup> (62 insns) + DWARF line rows for rtc.c:398.
     * Ordered callee relocs: rtc_pads_muxsel, rtc_pads_funsel, esp_dport_access_reg_read, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_funie, rtc_pads_pu, rtc_pads_pd.
     */
}

/* rtc_cmd_wakeup_conf rtc.c:3 @ rtc.o size 101B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4882c, 0x3ff48830
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_cmd_wakeup_conf(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_cmd_wakeup_conf> (36 insns) + DWARF line rows for rtc.c:3.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_get_st rtc.c:217 @ rtc.o size 17B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff480c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_get_st(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_get_st> (6 insns) + DWARF line rows for rtc.c:217.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_init_full rtc.c:235 @ rtc.o size 1042B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, rtc_init_clk | Data refs: esp_dport_access_reg_read, rtc_init_clk | MMIO: 0x3ff48000, 0x3ff4801c, 0x3ff48070, 0x3ff48078, 0x3ff4807c, 0x3ff48080, 0x3ff48084, 0x3ff48088, 0x3ff4808c, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_init_full(u32 fast_clk_sel, u32 ck12m_div, u32 ck12m_wait, u32 xtal_wait, u32 pll_wait, u32 ana_clk_sel, u32 slw_ck_dcap, u32 ck12m_dfreq, u32 pwrctl_init, u32 ck12m_fpu, u32 xtl_fpu, u32 bias_core_fpu, u32 bias_i2c_fpu, u32 bias_fnslp, u32 bbpll_fpu, u32 bbplli2c_fpu, u32 rtcreg_fpu, u32 rtcdboost_fpu, u32 dec_hbw, u32 inc_hbp, u32 rtc_dbias, u32 dig_dbias, u32 x32k_dac, u32 lslp_meminf_pd)
{
    (void)fast_clk_sel;
    (void)ck12m_div;
    (void)ck12m_wait;
    (void)xtal_wait;
    (void)pll_wait;
    (void)ana_clk_sel;
    (void)slw_ck_dcap;
    (void)ck12m_dfreq;
    (void)pwrctl_init;
    (void)ck12m_fpu;
    (void)xtl_fpu;
    (void)bias_core_fpu;
    (void)bias_i2c_fpu;
    (void)bias_fnslp;
    (void)bbpll_fpu;
    (void)bbplli2c_fpu;
    (void)rtcreg_fpu;
    (void)rtcdboost_fpu;
    (void)dec_hbw;
    (void)inc_hbp;
    (void)rtc_dbias;
    (void)dig_dbias;
    (void)x32k_dac;
    (void)lslp_meminf_pd;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_init_full> (378 insns) + DWARF line rows for rtc.c:235.
     * Ordered callee relocs: esp_dport_access_reg_read, rtc_init_clk.
     */
}

/* rtc_is_st_idle rtc.c:222 @ rtc.o size 23B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff480c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_is_st_idle(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_is_st_idle> (8 insns) + DWARF line rows for rtc.c:222.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pad_ext_wakeup rtc.c:379 @ rtc.o size 173B [dwarf-sig]
 * Calls: rtc_pads_muxsel, rtc_pads_funsel, esp_dport_access_reg_read, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_funie, rtc_pads_pu, rtc_pads_pd | Data refs: esp_dport_access_reg_read, rtc_pads_funie, rtc_pads_funsel, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe, rtc_pads_slpsel | MMIO: 0x3ff48060, 0x3ff4840c, 0x3ff484bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pad_ext_wakeup(u32 mask, u32 wakeup_sel, u32 wakeup_lv)
{
    (void)mask;
    (void)wakeup_sel;
    (void)wakeup_lv;
    /* DWARF locals: u32 i@l380, u32 filter@l381, u32 addr@l382 */
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pad_ext_wakeup> (65 insns) + DWARF line rows for rtc.c:379.
     * Ordered callee relocs: rtc_pads_muxsel, rtc_pads_funsel, esp_dport_access_reg_read, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_funie, rtc_pads_pu, rtc_pads_pd.
     */
}

/* rtc_pad_gpio_wakeup rtc.c:354 @ rtc.o size 183B [dwarf-sig]
 * Calls: rtc_pads_muxsel, rtc_pads_funsel, esp_dport_access_reg_read, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_funie, rtc_pads_pu, rtc_pads_pd | Data refs: esp_dport_access_reg_read, rtc_pads_funie, rtc_pads_funsel, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe, rtc_pads_slpsel | MMIO: 0x3ff4840c, 0x3ff48428, 0x3ff48470
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pad_gpio_wakeup(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* DWARF locals: u32 i@l355, u32 filter@l356, u32 addr@l357 */
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pad_gpio_wakeup> (69 insns) + DWARF line rows for rtc.c:354.
     * Ordered callee relocs: rtc_pads_muxsel, rtc_pads_funsel, esp_dport_access_reg_read, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_funie, rtc_pads_pu, rtc_pads_pd.
     */
}

/* rtc_pads_funie rtc.c:122 @ rtc.o size 768B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_funie(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_funie> (281 insns) + DWARF line rows for rtc.c:122.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_funsel rtc.c:35 @ rtc.o size 772B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_funsel(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_funsel> (282 insns) + DWARF line rows for rtc.c:35.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_hold rtc.c:179 @ rtc.o size 744B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_hold(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_hold> (275 insns) + DWARF line rows for rtc.c:179.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_muxsel rtc.c:13 @ rtc.o size 780B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_muxsel(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_muxsel> (284 insns) + DWARF line rows for rtc.c:13.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_pd rtc.c:162 @ rtc.o size 516B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_pd(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_pd> (188 insns) + DWARF line rows for rtc.c:162.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_pu rtc.c:145 @ rtc.o size 516B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_pu(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_pu> (188 insns) + DWARF line rows for rtc.c:145.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_slpie rtc.c:98 @ rtc.o size 768B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_slpie(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_slpie> (281 insns) + DWARF line rows for rtc.c:98.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_slpoe rtc.c:81 @ rtc.o size 512B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_slpoe(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_slpoe> (187 insns) + DWARF line rows for rtc.c:81.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_pads_slpsel rtc.c:57 @ rtc.o size 772B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_pads_slpsel(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_pads_slpsel> (282 insns) + DWARF line rows for rtc.c:57.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_powerdown_rf rtc.c:212 @ rtc.o size 27B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48030
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_powerdown_rf(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_powerdown_rf> (10 insns) + DWARF line rows for rtc.c:212.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_powerup_rf rtc.c:207 @ rtc.o size 27B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48030
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_powerup_rf(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_powerup_rf> (10 insns) + DWARF line rows for rtc.c:207.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_sdreg_off rtc.c:432 @ rtc.o size 65B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48074
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_sdreg_off(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_sdreg_off> (24 insns) + DWARF line rows for rtc.c:432.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_slp_prep_lite_12M rtc.c:444 @ rtc.o size 47B [dwarf-sig]
 * Calls: rtc_slp_prep | Data refs: rtc_slp_prep | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_slp_prep_lite_12M(u32 deep_slp, u32 cpu_lp_mode)
{
    (void)deep_slp;
    (void)cpu_lp_mode;
    /* DWARF locals: u32 soc_clk_sel@l445, u32 dig_bias_wak@l446 */
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_slp_prep_lite_12M> (22 insns) + DWARF line rows for rtc.c:444.
     * Ordered callee relocs: rtc_slp_prep.
     */
}

/* rtc_soc_clk_ck12m rtc.c:227 @ rtc.o size 63B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48000, 0x3ff48070
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_soc_clk_ck12m(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_soc_clk_ck12m> (22 insns) + DWARF line rows for rtc.c:227.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_wifi_force_pd rtc.c:417 @ rtc.o size 93B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff000cc, 0x3ff000d0, 0x3ff48084, 0x3ff48088
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_wifi_force_pd(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc.rdis
     * function <rtc_wifi_force_pd> (34 insns) + DWARF line rows for rtc.c:417.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* Undefined refs (3): esp_dport_access_reg_read, rtc_init_clk, rtc_slp_prep */