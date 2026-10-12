/* Reconstruction of rtc_analog.o (librtc.a)
 * CU: rtc_analog.c | comp_dir: /home/cff/gittree/chip_rtc/chip7.1_rtc/board_code/app_test/pp/rtc
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 27 | funcdb functions: 19
 * Disasm: re/esp32-phy/disasm/librtc/rtc_analog.rdis
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

/* adc1_amp_read rtc_analog.c:236 @ rtc_analog.o size 33B [dwarf-sig]
 * Calls: adc1_pad_init, adc1_amp_read_full | Data refs: adc1_amp_read_full, adc1_pad_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 adc1_amp_read(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc1_amp_read> (13 insns) + DWARF line rows for rtc_analog.c:236.
     * Ordered callee relocs: adc1_pad_init, adc1_amp_read_full.
     */
}

/* adc1_amp_read_full rtc_analog.c:194 @ rtc_analog.o size 540B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff48800, 0x3ff48808, 0x3ff4880c, 0x3ff48810, 0x3ff4882c, 0x3ff48834, 0x3ff48854
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 adc1_amp_read_full(uint8 pad, uint8 atten, uint16 stg1, uint16 stg2, uint16 stg3)
{
    (void)pad;
    (void)atten;
    (void)stg1;
    (void)stg2;
    (void)stg3;
    /* DWARF locals: uint16 vdd@l196 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc1_amp_read_full> (192 insns) + DWARF line rows for rtc_analog.c:194.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* adc1_pad_init rtc_analog.c:339 @ rtc_analog.o size 82B [dwarf-sig]
 * Calls: rtc_pads_muxsel, rtc_pads_pu, rtc_pads_pd, rtc_pads_funie, rtc_pads_slpie, rtc_pads_slpoe | Data refs: .rodata.CSWTCH$13, rtc_pads_funie, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void adc1_pad_init(u8 pad_en)
{
    (void)pad_en;
    /* DWARF locals: u32 rtc_pad_musk@l341 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc1_pad_init> (32 insns) + DWARF line rows for rtc_analog.c:339.
     * Ordered callee relocs: rtc_pads_muxsel, rtc_pads_pu, rtc_pads_pd, rtc_pads_funie, rtc_pads_slpie, rtc_pads_slpoe.
     */
}

/* adc1_read rtc_analog.c:188 @ rtc_analog.o size 32B [dwarf-sig]
 * Calls: adc1_pad_init, adc1_read_test | Data refs: adc1_pad_init, adc1_read_test | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 adc1_read(uint8 pad, uint8 atten)
{
    (void)pad;
    (void)atten;
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc1_read> (12 insns) + DWARF line rows for rtc_analog.c:188.
     * Ordered callee relocs: adc1_pad_init, adc1_read_test.
     */
}

/* adc1_read_test rtc_analog.c:138 @ rtc_analog.o size 512B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48800, 0x3ff48808, 0x3ff4880c, 0x3ff48810, 0x3ff4882c, 0x3ff48834, 0x3ff4883c, 0x3ff48854, 0x3ff488a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 adc1_read_test(uint8 pad, uint8 atten, uint16 pad_en_wait)
{
    (void)pad;
    (void)atten;
    (void)pad_en_wait;
    /* DWARF locals: uint16 vdd@l140 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc1_read_test> (183 insns) + DWARF line rows for rtc_analog.c:138.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* adc2_pad_init rtc_analog.c:380 @ rtc_analog.o size 84B [dwarf-sig]
 * Calls: rtc_pads_muxsel, rtc_pads_pu, rtc_pads_pd, rtc_pads_funie, rtc_pads_slpie, rtc_pads_slpoe | Data refs: .rodata.CSWTCH$19, rtc_pads_funie, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void adc2_pad_init(u8 pad_en)
{
    (void)pad_en;
    /* DWARF locals: u32 rtc_pad_musk@l382 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc2_pad_init> (33 insns) + DWARF line rows for rtc_analog.c:380.
     * Ordered callee relocs: rtc_pads_muxsel, rtc_pads_pu, rtc_pads_pd, rtc_pads_funie, rtc_pads_slpie, rtc_pads_slpoe.
     */
}

/* adc2_read rtc_analog.c:333 @ rtc_analog.o size 32B [dwarf-sig]
 * Calls: adc2_pad_init, adc2_read_test | Data refs: adc2_pad_init, adc2_read_test | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 adc2_read(uint8 pad, uint8 atten)
{
    (void)pad;
    (void)atten;
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc2_read> (12 insns) + DWARF line rows for rtc_analog.c:333.
     * Ordered callee relocs: adc2_pad_init, adc2_read_test.
     */
}

/* adc2_read_test rtc_analog.c:302 @ rtc_analog.o size 444B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4882c, 0x3ff48838, 0x3ff4883c, 0x3ff48890, 0x3ff48894, 0x3ff4e050
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 adc2_read_test(uint8 pad, uint8 atten)
{
    (void)pad;
    (void)atten;
    /* DWARF locals: uint16 vdd@l304 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc2_read_test> (157 insns) + DWARF line rows for rtc_analog.c:302.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* adc_pad_init rtc_analog.c:476 @ rtc_analog.o size 442B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff4848c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void adc_pad_init(u32 pad)
{
    (void)pad;
    /* DWARF locals: int i@l478 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc_pad_init> (158 insns) + DWARF line rows for rtc_analog.c:476.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* adc_pad_int rtc_analog.c:426 @ rtc_analog.o size 216B [dwarf-sig]
 * Calls: rtc_pads_pu, rtc_pads_pd, rtc_pads_funie, rtc_pads_slpie, rtc_pads_slpoe | Data refs: rtc_pads_funie, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void adc_pad_int(u8 adc_num, u32 adc1_channel, u32 adc2_channel)
{
    (void)adc_num;
    (void)adc1_channel;
    (void)adc2_channel;
    /* DWARF locals: u32 rtc_pad_musk@l427 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <adc_pad_int> (78 insns) + DWARF line rows for rtc_analog.c:426.
     * Ordered callee relocs: rtc_pads_pu, rtc_pads_pd, rtc_pads_funie, rtc_pads_slpie, rtc_pads_slpoe.
     */
}

/* dac_out rtc_analog.c:29 @ rtc_analog.o size 612B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48484, 0x3ff48488, 0x3ff48898, 0x3ff4889c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void dac_out(uint8 dac_en, u8 tone_en, uint16 dc_value, uint16 tone_scale, uint16 tone_step)
{
    (void)dac_en;
    (void)tone_en;
    (void)dc_value;
    (void)tone_scale;
    (void)tone_step;
    /* DWARF locals: u8 dc1_value@l31, u8 dc2_value@l32, u8 tone1_scale@l33, u8 tone2_scale@l34 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <dac_out> (219 insns) + DWARF line rows for rtc_analog.c:29.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* dac_pad_init rtc_analog.c:529 @ rtc_analog.o size 212B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48484, 0x3ff48488, 0x3ff48898, 0x3ff4889c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void dac_pad_init(u8 dac_pad, uint8 dac_val)
{
    (void)dac_pad;
    (void)dac_val;
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <dac_pad_init> (77 insns) + DWARF line rows for rtc_analog.c:529.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* get_vdd33 rtc_analog.c:106 @ rtc_analog.o size 251B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us, g_phyFuns | MMIO: 0x3ff4882c, 0x3ff4e050, 0x3ff4e05c, 0x3ff4e080, 0x3ff4e0a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 get_vdd33(void)
{
    /* DWARF locals: u32 sar_dout@l120, u32 mem_r@l121, u32 vdd33@l122, u8 i@l123 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <get_vdd33> (94 insns) + DWARF line rows for rtc_analog.c:106.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* hall_sens_amp_read rtc_analog.c:297 @ rtc_analog.o size 30B [dwarf-sig]
 * Calls: adc1_pad_init, hall_sens_amp_read_full | Data refs: adc1_pad_init, hall_sens_amp_read_full | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 hall_sens_amp_read(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <hall_sens_amp_read> (11 insns) + DWARF line rows for rtc_analog.c:297.
     * Ordered callee relocs: adc1_pad_init, hall_sens_amp_read_full.
     */
}

/* hall_sens_amp_read_full rtc_analog.c:274 @ rtc_analog.o size 209B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us, adc1_amp_read_full | Data refs: adc1_amp_read_full, esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff48478, 0x3ff48858, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 hall_sens_amp_read_full(uint16 stg1, uint16 stg2, uint16 stg3)
{
    (void)stg1;
    (void)stg2;
    (void)stg3;
    /* DWARF locals: u16 Sens_Vp0@l276, u16 Sens_Vp1@l277, S16 vdd@l278 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <hall_sens_amp_read_full> (76 insns) + DWARF line rows for rtc_analog.c:274.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us, adc1_amp_read_full.
     */
}

/* hall_sens_read rtc_analog.c:268 @ rtc_analog.o size 30B [dwarf-sig]
 * Calls: adc1_pad_init, hall_sens_read_full | Data refs: adc1_pad_init, hall_sens_read_full | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 hall_sens_read(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <hall_sens_read> (11 insns) + DWARF line rows for rtc_analog.c:268.
     * Ordered callee relocs: adc1_pad_init, hall_sens_read_full.
     */
}

/* hall_sens_read_full rtc_analog.c:241 @ rtc_analog.o size 225B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us, adc1_read_test | Data refs: adc1_read_test, esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff48478, 0x3ff48858, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 hall_sens_read_full(void)
{
    /* DWARF locals: u16 Sens_Vp0@l243, u16 Sens_Vn0@l244, u16 Sens_Vp1@l245, u16 Sens_Vn1@l246, S16 vdd@l247 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <hall_sens_read_full> (83 insns) + DWARF line rows for rtc_analog.c:241.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us, adc1_read_test.
     */
}

/* temprature_sens_read rtc_analog.c:6 @ rtc_analog.o size 206B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff48844, 0x3ff4884c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint8 temprature_sens_read(void)
{
    /* DWARF locals: uint8 temp@l8 */
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <temprature_sens_read> (73 insns) + DWARF line rows for rtc_analog.c:6.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* vdd33_init rtc_analog.c:83 @ rtc_analog.o size 294B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, g_phyFuns | MMIO: 0x3ff460c0, 0x3ff48030, 0x3ff4880c, 0x3ff4882c, 0x3ff48838, 0x3ff48890, 0x3ff48894, 0x3ff4e050, 0x3ff4e05c, 0x3ff66010, 0x3fffffff
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void vdd33_init(void)
{
    /* TODO(ground-truth): reconstruct from librtc/rtc_analog.rdis
     * function <vdd33_init> (105 insns) + DWARF line rows for rtc_analog.c:83.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* Undefined refs (9): esp_dport_access_reg_read, ets_delay_us, g_phyFuns, rtc_pads_funie, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe */