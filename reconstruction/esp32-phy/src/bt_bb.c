/* Reconstruction of bt_bb.o (librtc.a)
 * CU: bt_bb.c | comp_dir: /home/cff/gittree/chip_rtc/chip7.1_rtc/board_code/app_test/pp/rtc
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 25 | funcdb functions: 15
 * Disasm: re/esp32-phy/disasm/librtc/bt_bb.rdis
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

/* BT_init_rx_filters bt_bb.c:39 @ bt_bb.o size 596B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff51020, 0x3ff51028, 0x3ff5104c, 0x3ff51058, 0x3ff5105c, 0x3ff5106c, 0x3ff51084, 0x3ff5c07c, 0x3ff5c080, 0x3ff5c084, 0x3ff5c090, 0x3ff5c0d0, 0x60000000, 0x60032124
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_init_rx_filters(uint16 freq_offset_500k)
{
    (void)freq_offset_500k;
    /* DWARF locals: u32 i@l41, U32[] GFSK_LP24@l42, U32[] DPSK_LP40@l46 */
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <BT_init_rx_filters> (211 insns) + DWARF line rows for bt_bb.c:39.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* BT_tx_8m_enable bt_bb.c:14 @ bt_bb.o size 126B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff51000, 0x3ff51014, 0x3ff51040, 0x3ff51044
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_8m_enable(unsigned int hoppe_n500k)
{
    (void)hoppe_n500k;
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <BT_tx_8m_enable> (46 insns) + DWARF line rows for bt_bb.c:14.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* BT_tx_if_init bt_bb.c:26 @ bt_bb.o size 150B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read, phy_get_fetx_delay | Data refs: esp_dport_access_reg_read, phy_get_fetx_delay | MMIO: 0x3ff5103c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_if_init(unsigned int guard, unsigned int tx_on_ahead, unsigned int tx_on_behind, unsigned int init_tx_DC)
{
    (void)guard;
    (void)tx_on_ahead;
    (void)tx_on_behind;
    (void)init_tx_DC;
    /* DWARF locals: uint16 fetx_delay@l29 */
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <BT_tx_if_init> (53 insns) + DWARF line rows for bt_bb.c:26.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_get_fetx_delay.
     */
}

/* bt_bb_init_cmplx bt_bb.c:176 @ bt_bb.o size 290B [dwarf-sig]
 * Calls: phy_dis_hw_set_freq, ets_delay_us, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, esp_dport_access_reg_read, phy_en_hw_set_freq | Data refs: BT_init_rx_filters, BT_tx_8m_enable, BT_tx_if_init, esp_dport_access_reg_read, ets_delay_us, phy_dis_hw_set_freq, phy_en_hw_set_freq | MMIO: 0x3ff51040, 0x6000604c, 0x600320dc, 0x600320f0, 0x600320f4, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_init_cmplx(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <bt_bb_init_cmplx> (103 insns) + DWARF line rows for bt_bb.c:176.
     * Ordered callee relocs: phy_dis_hw_set_freq, ets_delay_us, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, esp_dport_access_reg_read, phy_en_hw_set_freq.
     */
}

/* bt_bb_init_cmplx_reg bt_bb.c:247 @ bt_bb.o size 67B [dwarf-sig]
 * Calls: BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, esp_dport_access_reg_read | Data refs: BT_init_rx_filters, BT_tx_8m_enable, BT_tx_if_init, esp_dport_access_reg_read | MMIO: 0x3ff51040
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_init_cmplx_reg(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <bt_bb_init_cmplx_reg> (24 insns) + DWARF line rows for bt_bb.c:247.
     * Ordered callee relocs: BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, esp_dport_access_reg_read.
     */
}

/* bt_bb_version bt_bb.c:437 @ bt_bb.o size 23B [dwarf-sig]
 * Calls: rtc_printf | Data refs: .rodata.str1.4, rtc_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_version(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <bt_bb_version> (8 insns) + DWARF line rows for bt_bb.c:437.
     * Ordered callee relocs: rtc_printf.
     */
}

/* bt_cmplx_hq_re bt_bb.c:429 @ bt_bb.o size 29B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 bt_cmplx_hq_re(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <bt_cmplx_hq_re> (12 insns) + DWARF line rows for bt_bb.c:429.
     */
}

/* bt_cmplx_lq_re bt_bb.c:433 @ bt_bb.o size 29B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 bt_cmplx_lq_re(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <bt_cmplx_lq_re> (12 insns) + DWARF line rows for bt_bb.c:433.
     */
}

/* bt_dgmixer_fstep_250k bt_bb.c:162 @ bt_bb.o size 33B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff51040
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_dgmixer_fstep_250k(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <bt_dgmixer_fstep_250k> (12 insns) + DWARF line rows for bt_bb.c:162.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* bt_rfoffset_en bt_bb.c:166 @ bt_bb.o size 69B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff51020, 0x3ff51040
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_rfoffset_en(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <bt_rfoffset_en> (25 insns) + DWARF line rows for bt_bb.c:166.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* coex_bt_high_prio bt_bb.c:379 @ bt_bb.o size 301B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c080, 0x3ff5d040, 0x600041c4, 0x600310d0, 0x60031300, 0x60033d30, 0x60033d38, 0x60033d40
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void coex_bt_high_prio(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <coex_bt_high_prio> (107 insns) + DWARF line rows for bt_bb.c:379.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* force_bt_mode bt_bb.c:271 @ bt_bb.o size 222B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c080, 0x3ff5d040, 0x600041c4, 0x600310d0, 0x60031300, 0x60033d30, 0x60033d38, 0x60033d40
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void force_bt_mode(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <force_bt_mode> (80 insns) + DWARF line rows for bt_bb.c:271.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* force_wifi_mode bt_bb.c:292 @ bt_bb.o size 170B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_force_wifi_chan | Data refs: esp_dport_access_reg_read, force_wifi_mode_on, phy_force_wifi_chan | MMIO: 0x3ff51098, 0x3ff5c080, 0x3ff5d040, 0x600041c4, 0x600310d0, 0x60031300
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void force_wifi_mode(u32 bt_mux_off)
{
    (void)bt_mux_off;
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <force_wifi_mode> (62 insns) + DWARF line rows for bt_bb.c:292.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_force_wifi_chan.
     */
}

/* rw_coex_on bt_bb.c:259 @ bt_bb.o size 127B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x600310d0, 0x60031300, 0x60033d30, 0x60033d38
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_coex_on(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <rw_coex_on> (45 insns) + DWARF line rows for bt_bb.c:259.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* unforce_wifi_mode bt_bb.c:334 @ bt_bb.o size 138B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_unforce_wifi_chan | Data refs: esp_dport_access_reg_read, force_wifi_mode_on, phy_unforce_wifi_chan | MMIO: 0x3ff51098, 0x3ff5110c, 0x3ff5c080, 0x3ff5d040, 0x600041c4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void unforce_wifi_mode(void)
{
    /* TODO(ground-truth): reconstruct from librtc/bt_bb.rdis
     * function <unforce_wifi_mode> (50 insns) + DWARF line rows for bt_bb.c:334.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_unforce_wifi_chan.
     */
}

/* Undefined refs (9): esp_dport_access_reg_read, ets_delay_us, g_phyFuns, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_force_wifi_chan, phy_get_fetx_delay, phy_unforce_wifi_chan, rtc_printf */