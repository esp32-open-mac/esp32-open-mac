/* Reconstruction of rtc_cntl.o (librtc.a)
 * CU: rtc_cntl.c | comp_dir: /home/cff/gittree/chip_rtc/chip7.1_rtc/board_code/app_test/pp/rtc
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 6 | funcdb functions: 4
 * Disasm: re/esp32-phy/disasm/librtc/rtc_cntl.rdis
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

/* rtc_digital_lp_mode_off_stg1 rtc_cntl.c:35 @ rtc_cntl.o size 158B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, rtc_wifi_force_pd_off, rtc_dbias_cfg | Data refs: esp_dport_access_reg_read, rtc_dbias_cfg, rtc_wifi_force_pd_off | MMIO: 0x3ff000c0, 0x3ff000cc, 0x3ff48000, 0x3ff48084, 0x3ff48088
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_digital_lp_mode_off_stg1(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc_cntl.rdis
     * function <rtc_digital_lp_mode_off_stg1> (59 insns) + DWARF line rows for rtc_cntl.c:35.
     * Ordered callee relocs: esp_dport_access_reg_read, rtc_wifi_force_pd_off, rtc_dbias_cfg.
     */
}

/* rtc_digital_lp_mode_off_stg2 rtc_cntl.c:50 @ rtc_cntl.o size 27B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_digital_lp_mode_off_stg2(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc_cntl.rdis
     * function <rtc_digital_lp_mode_off_stg2> (10 insns) + DWARF line rows for rtc_cntl.c:50.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_sar_sleep_timer_start rtc_cntl.c:55 @ rtc_cntl.o size 98B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48818, 0x3ff4882c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_sar_sleep_timer_start(u32 cycles)
{
    (void)cycles;
    /* TODO(ground-truth): reconstruct from librtc/rtc_cntl.rdis
     * function <rtc_sar_sleep_timer_start> (37 insns) + DWARF line rows for rtc_cntl.c:55.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_wifi_force_pd_off rtc_cntl.c:19 @ rtc_cntl.o size 93B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff000cc, 0x3ff000d0, 0x3ff48084, 0x3ff48088
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_wifi_force_pd_off(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc_cntl.rdis
     * function <rtc_wifi_force_pd_off> (34 insns) + DWARF line rows for rtc_cntl.c:19.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* Undefined refs (2): esp_dport_access_reg_read, rtc_dbias_cfg */