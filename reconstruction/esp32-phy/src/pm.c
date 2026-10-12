/* Reconstruction of pm.o (librtc.a)
 * CU: pm.c | comp_dir: /home/cff/gittree/chip_rtc/chip7.1_rtc/board_code/app_test/pp/rtc
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 29 | funcdb functions: 16
 * Disasm: re/esp32-phy/disasm/librtc/pm.rdis
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

/* get_chip_version pm.c:48 @ pm.o size 10B [dwarf-sig]
 * Calls: (none) | Data refs: chip_version | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 get_chip_version(void)
{
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <get_chip_version> (4 insns) + DWARF line rows for pm.c:48.
     */
}

/* pm_check_mac_idle pm.c:153 @ pm.o size 7B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool pm_check_mac_idle(void)
{
    /* DWARF locals: bool reject@l156 */
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_check_mac_idle> (3 insns) + DWARF line rows for pm.c:153.
     */
}

/* pm_goto_sleep pm.c:106 @ pm.o size 96B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: SDIO_slp_reject, esp_dport_access_reg_read, software_slp_reject | MMIO: 0x3ff48018, 0x3ff48040, 0x3ff48048
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 pm_goto_sleep(u32 sleep_mode)
{
    (void)sleep_mode;
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_goto_sleep> (36 insns) + DWARF line rows for pm.c:106.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* pm_mac_deinit pm.c:131 @ pm.o size 11B [dwarf-sig-decl]
 * Calls: pm_sleep_set_mac | Data refs: pm_sleep_set_mac | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pm_mac_deinit(void)
{
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_mac_deinit> (4 insns) + DWARF line rows for pm.c:131.
     * Ordered callee relocs: pm_sleep_set_mac.
     */
}

/* pm_mac_init pm.c:185 @ pm.o size 27B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x60033cb8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pm_mac_init(void)
{
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_mac_init> (10 insns) + DWARF line rows for pm.c:185.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* pm_prepare_to_sleep pm.c:? @ pm.o size 5B [inferred]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void pm_prepare_to_sleep(void)
{
    return;
}

/* pm_rtc_clock_cali pm.c:63 @ pm.o size 50B [dwarf-sig]
 * Calls: rtc_slowck_cali | Data refs: rtc_slowck_cali | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pm_rtc_clock_cali(RTC_clock * RTC)
{
    (void)RTC;
    /* DWARF locals: u32 cali_value@l65, u32 period@l65, u32 delta@l65, u32 rtc90cycle2us@l66 */
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_rtc_clock_cali> (19 insns) + DWARF line rows for pm.c:63.
     * Ordered callee relocs: rtc_slowck_cali.
     */
}

/* pm_sdio_nidle pm.c:101 @ pm.o size 7B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 pm_sdio_nidle(void)
{
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_sdio_nidle> (3 insns) + DWARF line rows for pm.c:101.
     */
}

/* pm_set_sleep_btco pm.c:170 @ pm.o size 5B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void pm_set_sleep_btco(void)
{
    return;
}

/* pm_set_sleep_cycles pm.c:53 @ pm.o size 47B [dwarf-sig]
 * Calls: rtc_time_get, rtc_sleep_set_wakeup_time | Data refs: periodic_cal_sat, rtc_sleep_set_wakeup_time, rtc_time_get | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pm_set_sleep_cycles(u32 sleep_cycles)
{
    (void)sleep_cycles;
    /* DWARF locals: u64 cur_time@l55, u64 target@l56 */
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_set_sleep_cycles> (18 insns) + DWARF line rows for pm.c:53.
     * Ordered callee relocs: rtc_time_get, rtc_sleep_set_wakeup_time.
     */
}

/* pm_set_sleep_mode_full pm.c:191 @ pm.o size 778B [dwarf-sig]
 * Calls: phy_close_rf, pm_sleep_set_mac, esp_dport_access_reg_read, ets_delay_us, rtc_slp_prep, uart_div_modify, rtc_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_delay_us, phy_close_rf, pm_sleep_set_mac, rtc_printf, rtc_slp_prep, uart_div_modify | MMIO: 0x3ff48000, 0x3ff48078, 0x3ff48080, 0x3ff48084, 0x3ff48088, 0x3ff480b4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
SW_REJECT_TYPE pm_set_sleep_mode_full(u32 sleep_mode, void (*)() * pmac_save_params)
{
    (void)sleep_mode;
    (void)pmac_save_params;
    /* DWARF locals: u32 soc_clk_sel@l193, u32 lslp_mem_inf_fpu@l194, u32 rtc_mem_inf_fpu@l195, u32 rtc_mem_inf_folw_cpu@l196, u32 rtc_mem_pd@l197, u32 rtc_peri_pd_en@l198, u32 wifi_pd_en@l199, u32 rom_mem_pd_en@l200, u32 deep_slp@l201, u32 wdt_flashboot_mod_on@l202, u32 cpu_lp_mode@l203, u32 dig_dbias_wak@l204, u32 dig_dbias_slp@l205, u32 rtc_dbias_wak@l206, u32 rtc_dbias_slp@l207, u32 dbg_cfg@l208 */
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_set_sleep_mode_full> (299 insns) + DWARF line rows for pm.c:191.
     * Ordered callee relocs: phy_close_rf, pm_sleep_set_mac, esp_dport_access_reg_read, ets_delay_us, rtc_slp_prep, uart_div_modify, rtc_printf.
     */
}

/* pm_set_wakeup_btco pm.c:175 @ pm.o size 5B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void pm_set_wakeup_btco(void)
{
    return;
}

/* pm_set_wakeup_mac pm.c:147 @ pm.o size 27B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x60033cb8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pm_set_wakeup_mac(void)
{
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_set_wakeup_mac> (10 insns) + DWARF line rows for pm.c:147.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* pm_sleep_set_mac pm.c:137 @ pm.o size 103B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x60033cb8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pm_sleep_set_mac(void)
{
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_sleep_set_mac> (38 insns) + DWARF line rows for pm.c:137.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* pm_unmask_bt pm.c:180 @ pm.o size 5B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void pm_unmask_bt(u8 tw)
{
    return;
}

/* pm_wakeup_opt pm.c:42 @ pm.o size 44B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48038, 0x3ff48064
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pm_wakeup_opt(u32 wakeup_opt, u32 reject_opt)
{
    (void)wakeup_opt;
    (void)reject_opt;
    /* TODO(ground-truth): reconstruct from librtc/pm.rdis
     * function <pm_wakeup_opt> (16 insns) + DWARF line rows for pm.c:42.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* Undefined refs (9): esp_dport_access_reg_read, ets_delay_us, phy_close_rf, rtc_printf, rtc_sleep_set_wakeup_time, rtc_slowck_cali, rtc_slp_prep, rtc_time_get, uart_div_modify */