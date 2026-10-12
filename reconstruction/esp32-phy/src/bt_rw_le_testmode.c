/* Reconstruction of bt_rw_le_testmode.o (libbttestmode.a)
 * CU: bt_rw_le_testmode.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 80 | funcdb functions: 54
 * Disasm: re/esp32-phy/disasm/libbttestmode/bt_rw_le_testmode.rdis
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

/* MMIO helpers (same convention as other reconstructed TUs). */
#define REG_READ(a) (*(volatile u32 *)(a))
#define REG_WRITE(a, v) (*(volatile u32 *)(a) = (v))

/* Same-TU forward declarations (callees defined later in file). */
void rw_le_rxstat_unpack(u32 desc_addr, u32 * rxlinklbl, u32 * rxpriverr, u32 * rxtimeerr, u32 * rxbdaddrmatch, u32 * rxnesnerr, u32 * rxsnerr, u32 * rxmicerr, u32 * rxcrcerr, u32 * rxlenerr, u32 * rxtyperr, u32 * rxsyncerr, s8 * rxrssi);

/* esp_get_lerx_result bt_rw_le_testmode.c:1726 @ bt_rw_le_testmode.o size 28B [dwarf-sig]
 * Calls: (none) | Data refs: esp_rx_result, esp_rx_valid | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool esp_get_lerx_result(int32 * rx_result)
{
    (void)rx_result;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <esp_get_lerx_result> (12 insns) + DWARF line rows for bt_rw_le_testmode.c:1726.
     */
}

/* fcc_le_tx bt_rw_le_testmode.c:1308 @ bt_rw_le_testmode.o size 63B [dwarf-sig]
 * Calls: rw_le_tx_nohoppe | Data refs: rw_le_tx_nohoppe | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_le_tx(u32 txpwr, u32 chan, u32 len, u32 data_type, u32 tx_num_in)
{
    (void)txpwr;
    (void)chan;
    (void)len;
    (void)data_type;
    (void)tx_num_in;
    /* DWARF locals: u32 fi@l1309 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <fcc_le_tx> (25 insns) + DWARF line rows for bt_rw_le_testmode.c:1308.
     * Ordered callee relocs: rw_le_tx_nohoppe.
     */
}

/* fcc_le_tx_syncw bt_rw_le_testmode.c:1328 @ bt_rw_le_testmode.o size 66B [dwarf-sig]
 * Calls: rw_le_tx_nohoppe_syncw | Data refs: rw_le_tx_nohoppe_syncw | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_le_tx_syncw(u32 txpwr, u32 chan, u32 len, u32 data_type, u32 syncw, u32 tx_num_in)
{
    (void)txpwr;
    (void)chan;
    (void)len;
    (void)data_type;
    (void)syncw;
    (void)tx_num_in;
    /* DWARF locals: u32 fi@l1329 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <fcc_le_tx_syncw> (26 insns) + DWARF line rows for bt_rw_le_testmode.c:1328.
     * Ordered callee relocs: rw_le_tx_nohoppe_syncw.
     */
}

/* freq_print bt_rw_le_testmode.c:948 @ bt_rw_le_testmode.o size 60B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ff4e0c0, 0x3ff4e3fc, 0x3ff51030, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void freq_print(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <freq_print> (22 insns) + DWARF line rows for bt_rw_le_testmode.c:948.
     * Ordered callee relocs: phy_printf.
     */
}

/* get_bt_rx_rssi bt_rw_le_testmode.c:1734 @ bt_rw_le_testmode.o size 76B [dwarf-sig-decl]
 * Calls: (none) | Data refs: bt_2480_opt_en, bt_rx_rssi | MMIO: 0x3ff5c0d0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_bt_rx_rssi(u32 * pwr_in_band, u32 * gain, u32 * pwr_full_band, u32 total_p)
{
    (void)pwr_in_band;
    (void)gain;
    (void)pwr_full_band;
    (void)total_p;
    /* DWARF locals: bool bt_2480_opt_en@l1736, uint16 pwr_fine_set@l1737 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <get_bt_rx_rssi> (31 insns) + DWARF line rows for bt_rw_le_testmode.c:1734.
     */
}

/* hoppe_print bt_rw_le_testmode.c:958 @ bt_rw_le_testmode.o size 35B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51030, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void hoppe_print(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <hoppe_print> (13 insns) + DWARF line rows for bt_rw_le_testmode.c:958.
     */
}

/* rw_evt_refresh bt_rw_le_testmode.c:392 @ bt_rw_le_testmode.o size 24B [dwarf-sig-decl]
 * Calls: .text.rw_evt_refresh$part$0+0x28 | Data refs: (none) | MMIO: 0x60031214
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_evt_refresh(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l393, u32 i@l394, u32 data@l395 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_evt_refresh> (9 insns) + DWARF line rows for bt_rw_le_testmode.c:392.
     * Ordered callee relocs: .text.rw_evt_refresh$part$0+0x28.
     */
}

/* rw_evt_refresh$part$0 bt_rw_le_testmode.c:392 @ bt_rw_le_testmode.o size 145B [dwarf-sig-base-decl]
 * Calls: rw_le_rx_status_print | Data refs: evt_refresh_ind, rw_le_rx_status_print | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02d0, 0x60031218
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_evt_refresh$part$0(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l393, u32 i@l394, u32 data@l395 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_evt_refresh$part$0> (54 insns) + DWARF line rows for bt_rw_le_testmode.c:392.
     * Ordered callee relocs: rw_le_rx_status_print.
     */
}

/* rw_evt_refresh_check_rx bt_rw_le_testmode.c:460 @ bt_rw_le_testmode.o size 304B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, evt_refresh_ind, phy_printf | MMIO: 0x3ff51050, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02d0, 0x3ffb02d4, 0x60031214, 0x60031218
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_evt_refresh_check_rx(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l461, u32 i@l462, u32 data@l463, u32 rx_status0@l464, u32 rx_status1@l464, u32 rssi0@l464, u32 rssi1@l464, u32 warn@l464 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_evt_refresh_check_rx> (112 insns) + DWARF line rows for bt_rw_le_testmode.c:460.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_evtcntl_fsm_print bt_rw_le_testmode.c:618 @ bt_rw_le_testmode.o size 191B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_evtcntl_fsm_print, .rodata.str1.4, evtcntl_fsm_data_last, evtcntl_fsm_print_start, phy_printf | MMIO: 0x60031250, 0x60031254
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_evtcntl_fsm_print(void)
{
    /* DWARF locals: u32 print@l619, u32 evtcntl_fsm_data@l622 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_evtcntl_fsm_print> (68 insns) + DWARF line rows for bt_rw_le_testmode.c:618.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_evtcntladv_fsm_print bt_rw_le_testmode.c:674 @ bt_rw_le_testmode.o size 170B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_evtcntladv_fsm_print, .rodata.str1.4, evtcntladv_fsm_data_last, evtcntladv_fsm_print_start, phy_printf | MMIO: 0x60031250, 0x60031254
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_evtcntladv_fsm_print(void)
{
    /* DWARF locals: u32 print@l675, u32 evtcntladv_fsm_data@l678 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_evtcntladv_fsm_print> (61 insns) + DWARF line rows for bt_rw_le_testmode.c:674.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_evtschdl_fsm_print bt_rw_le_testmode.c:574 @ bt_rw_le_testmode.o size 191B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_evtschdl_fsm_print, .rodata.str1.4, evtschdl_fsm_data_last, evtschdl_fsm_print_start, phy_printf | MMIO: 0x60031250, 0x60031254
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_evtschdl_fsm_print(void)
{
    /* DWARF locals: u32 print@l575, u32 evtschdl_fsm_data@l578 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_evtschdl_fsm_print> (67 insns) + DWARF line rows for bt_rw_le_testmode.c:574.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_fill_adv_buf bt_rw_le_testmode.c:757 @ bt_rw_le_testmode.o size 27B [dwarf-sig-decl]
 * Calls: (none) | Data refs: ADV_payload | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_fill_adv_buf(u32 ptr)
{
    (void)ptr;
    /* DWARF locals: u32 i@l758 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_fill_adv_buf> (11 insns) + DWARF line rows for bt_rw_le_testmode.c:757.
     */
}

/* rw_fill_scanrsp_buf bt_rw_le_testmode.c:764 @ bt_rw_le_testmode.o size 25B [dwarf-sig-decl]
 * Calls: (none) | Data refs: SCAN_RSP_payload | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_fill_scanrsp_buf(u32 ptr)
{
    (void)ptr;
    /* DWARF locals: u32 i@l765 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_fill_scanrsp_buf> (10 insns) + DWARF line rows for bt_rw_le_testmode.c:764.
     */
}

/* rw_le_adv bt_rw_le_testmode.c:828 @ bt_rw_le_testmode.o size 315B [dwarf-sig]
 * Calls: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_adv_init, rw_le_core_on, rw_le_error_print, .text.rw_evt_refresh$part$0+0x28 | Data refs: .rodata.str1.4, phy_printf, rw_dm_activate, rw_init_em_radio_table, rw_le_adv_init, rw_le_core_off, rw_le_core_on, rw_le_error_print, rw_le_et_init | MMIO: 0x3ffb02a0, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031214, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_adv(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_adv> (113 insns) + DWARF line rows for bt_rw_le_testmode.c:828.
     * Ordered callee relocs: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_adv_init, rw_le_core_on, rw_le_error_print, .text.rw_evt_refresh$part$0+0x28.
     */
}

/* rw_le_adv_cmd bt_rw_le_testmode.c:2272 @ bt_rw_le_testmode.o size 294B [dwarf-sig]
 * Calls: rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_adv_init, rw_le_core_on | Data refs: rw_dm_activate, rw_init_em_radio_table, rw_le_adv_init, rw_le_core_off, rw_le_core_on, rw_le_et_init | MMIO: 0x3ffb0210, 0x3ffb02a0, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_adv_cmd(u32 txpwr)
{
    (void)txpwr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_adv_cmd> (107 insns) + DWARF line rows for bt_rw_le_testmode.c:2272.
     * Ordered callee relocs: rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_adv_init, rw_le_core_on.
     */
}

/* rw_le_adv_init bt_rw_le_testmode.c:772 @ bt_rw_le_testmode.o size 286B [dwarf-sig]
 * Calls: rw_le_init_cs | Data refs: ADV_payload, SCAN_RSP_payload, rw_le_init_cs | MMIO: 0x3ffb0300, 0x3ffb0400, 0x3ffb0404, 0x3ffb0408, 0x3ffb040c, 0x3ffb0410, 0x60031224, 0x60031228, 0x600312a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_adv_init(u32 tx_desc0, u32 tx_desc1, u32 format, u32 bdaddrl, u32 bdaddrh, u32 interval)
{
    (void)tx_desc0;
    (void)tx_desc1;
    (void)format;
    (void)bdaddrl;
    (void)bdaddrh;
    (void)interval;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_adv_init> (112 insns) + DWARF line rows for bt_rw_le_testmode.c:772.
     * Ordered callee relocs: rw_le_init_cs.
     */
}

/* rw_le_adv_test_init bt_rw_le_testmode.c:929 @ bt_rw_le_testmode.o size 276B [dwarf-sig]
 * Calls: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_adv_init, rw_le_core_on | Data refs: .rodata.str1.4, phy_printf, rw_dm_activate, rw_init_em_radio_table, rw_le_adv_init, rw_le_core_off, rw_le_core_on, rw_le_et_init | MMIO: 0x3ffb02a0, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_adv_test_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_adv_test_init> (100 insns) + DWARF line rows for bt_rw_le_testmode.c:929.
     * Ordered callee relocs: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_adv_init, rw_le_core_on.
     */
}

/* rw_le_advscan bt_rw_le_testmode.c:860 @ bt_rw_le_testmode.o size 331B [dwarf-sig]
 * Calls: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_advscan_init, rw_le_core_on, rw_le_error_print, rw_le_scan_print, .text.rw_le_scan_refresh$part$1+0x44 | Data refs: .rodata.str1.4, phy_printf, rw_dm_activate, rw_init_em_radio_table, rw_le_advscan_init, rw_le_core_off, rw_le_core_on, rw_le_error_print, rw_le_et_init, rw_le_scan_print | MMIO: 0x3ffb02a0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031214, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_advscan(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_advscan> (119 insns) + DWARF line rows for bt_rw_le_testmode.c:860.
     * Ordered callee relocs: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_advscan_init, rw_le_core_on, rw_le_error_print, rw_le_scan_print, .text.rw_le_scan_refresh$part$1+0x44.
     */
}

/* rw_le_advscan_init bt_rw_le_testmode.c:794 @ bt_rw_le_testmode.o size 168B [dwarf-sig]
 * Calls: rw_le_init_cs | Data refs: rw_le_init_cs | MMIO: 0x60031224, 0x60031228, 0x600312a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_advscan_init(u32 tx_desc0, u32 format, u32 bdaddrl, u32 bdaddrh, u32 interval)
{
    (void)tx_desc0;
    (void)format;
    (void)bdaddrl;
    (void)bdaddrh;
    (void)interval;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_advscan_init> (66 insns) + DWARF line rows for bt_rw_le_testmode.c:794.
     * Ordered callee relocs: rw_le_init_cs.
     */
}

/* rw_le_advscan_test_init bt_rw_le_testmode.c:895 @ bt_rw_le_testmode.o size 279B [dwarf-sig]
 * Calls: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_advscan_init, rw_le_core_on | Data refs: .rodata.str1.4, phy_printf, rw_dm_activate, rw_init_em_radio_table, rw_le_advscan_init, rw_le_core_off, rw_le_core_on, rw_le_et_init | MMIO: 0x3ffb02a0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_advscan_test_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_advscan_test_init> (101 insns) + DWARF line rows for bt_rw_le_testmode.c:895.
     * Ordered callee relocs: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_et_init, rw_le_advscan_init, rw_le_core_on.
     */
}

/* rw_le_cs_set_freq bt_rw_le_testmode.c:293 @ bt_rw_le_testmode.o size 27B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_cs_set_freq(u32 addr, u32 freq)
{
    (void)addr;
    (void)freq;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_cs_set_freq> (10 insns) + DWARF line rows for bt_rw_le_testmode.c:293.
     */
}

/* rw_le_cs_set_txdesc bt_rw_le_testmode.c:297 @ bt_rw_le_testmode.o size 30B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_cs_set_txdesc(u32 addr, u32 desc)
{
    (void)addr;
    (void)desc;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_cs_set_txdesc> (11 insns) + DWARF line rows for bt_rw_le_testmode.c:297.
     */
}

/* rw_le_cs_set_txpwr bt_rw_le_testmode.c:283 @ bt_rw_le_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0210
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_cs_set_txpwr(u32 txpwr)
{
    (void)txpwr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_cs_set_txpwr> (12 insns) + DWARF line rows for bt_rw_le_testmode.c:283.
     */
}

/* rw_le_error_print bt_rw_le_testmode.c:740 @ bt_rw_le_testmode.o size 63B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, le_error_data_last, le_error_print_start, phy_printf | MMIO: 0x60031260
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_error_print(void)
{
    /* DWARF locals: u32 print@l741, u32 le_error_data@l742 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_error_print> (23 insns) + DWARF line rows for bt_rw_le_testmode.c:740.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_le_et_init bt_rw_le_testmode.c:38 @ bt_rw_le_testmode.o size 151B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x3ffb0004, 0x3ffb0008, 0x3ffb000c, 0x3ffb0010, 0x3ffb0014, 0x3ffb0018, 0x3ffb001c, 0x3ffb0020, 0x3ffb0024, 0x3ffb0028, 0x3ffb002c, 0x3ffb0030, 0x3ffb0034, 0x3ffb0038, 0x3ffb003c, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_et_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_et_init> (57 insns) + DWARF line rows for bt_rw_le_testmode.c:38.
     */
}

/* rw_le_et_on_mask bt_rw_le_testmode.c:25 @ bt_rw_le_testmode.o size 57B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_et_on_mask(u32 mask)
{
    (void)mask;
    /* DWARF locals: u32 i@l29 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_et_on_mask> (21 insns) + DWARF line rows for bt_rw_le_testmode.c:25.
     */
}

/* rw_le_init_cs bt_rw_le_testmode.c:227 @ bt_rw_le_testmode.o size 647B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0200, 0x3ffb0204, 0x3ffb0208, 0x3ffb020c, 0x3ffb0210, 0x3ffb0214, 0x3ffb0218, 0x3ffb021c, 0x3ffb0220, 0x3ffb0224, 0x3ffb0228, 0x3ffb022c, 0x3ffb0230, 0x3ffb0234, 0x3ffb0238, 0x3ffb023c, 0x3ffb0240, 0x3ffb0244, 0x3ffb0248, 0x3ffb024c, 0x3ffb0250, 0x3ffb0254, 0x3ffb0258, 0x3ffb025c, 0x3ffb0260, 0x3ffb026c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_init_cs(u32 format, u32 sync_word, u32 crc_init, u32 ral_en, u32 ral_mode, u32 local_rpa_sel, u32 filter_policy, u32 ch_idx, u32 hopint, u32 fh_en, u32 txpwr, u32 rxwide, u32 rxwinsz, u32 txdesc, u32 maxevtime)
{
    (void)format;
    (void)sync_word;
    (void)crc_init;
    (void)ral_en;
    (void)ral_mode;
    (void)local_rpa_sel;
    (void)filter_policy;
    (void)ch_idx;
    (void)hopint;
    (void)fh_en;
    (void)txpwr;
    (void)rxwide;
    (void)rxwinsz;
    (void)txdesc;
    (void)maxevtime;
    /* DWARF locals: u32 maxrxbuf@l260 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_init_cs> (240 insns) + DWARF line rows for bt_rw_le_testmode.c:227.
     */
}

/* rw_le_init_rx_descryptor bt_rw_le_testmode.c:312 @ bt_rw_le_testmode.o size 85B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_init_rx_descryptor(u32 ptr, u32 nxt_ptr, u32 bufptr, u32 ralptr)
{
    (void)ptr;
    (void)nxt_ptr;
    (void)bufptr;
    (void)ralptr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_init_rx_descryptor> (32 insns) + DWARF line rows for bt_rw_le_testmode.c:312.
     */
}

/* rw_le_init_tx_descriptor bt_rw_le_testmode.c:301 @ bt_rw_le_testmode.o size 139B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_init_tx_descriptor(u32 is_connevt, u32 ptr, u32 nxt_ptr, u32 llid, u32 nesn, u32 sn, u32 md, u32 len, u32 type, u32 txadd, u32 rxadd, u32 advlen, u32 bufptr)
{
    (void)is_connevt;
    (void)ptr;
    (void)nxt_ptr;
    (void)llid;
    (void)nesn;
    (void)sn;
    (void)md;
    (void)len;
    (void)type;
    (void)txadd;
    (void)rxadd;
    (void)advlen;
    (void)bufptr;
    /* DWARF locals: u32 data0@l303 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_init_tx_descriptor> (51 insns) + DWARF line rows for bt_rw_le_testmode.c:301.
     */
}

/* rw_le_rx_per bt_rw_le_testmode.c:1592 @ bt_rw_le_testmode.o size 1390B [dwarf-sig]
 * Calls: rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_init_cs, rw_le_core_on, phy_printf, ets_delay_us, rw_bb_rx_refesh, GetStopCmd, rw_le_rxstat_unpack | Data refs: .rodata.str1.4, GetStopCmd, ets_delay_us, phy_printf, rw_bb_rx_refesh, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_init_cs, rw_le_rxstat_unpack | MMIO: 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ff51098, 0x3ffb0000, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031200, 0x60031214, 0x60031218, 0x60031224, 0x60031228, 0x6003122c, 0x600312a0, 0x600312e0, 0x600312f0
 * Fidelity: medium - LE init/RMW chain, EM programming, refresh/stop poll,
 *   dual-descriptor unpack, error ladder, gain accumulate and 21-lane print
 *   verified; counter-name routing approximate (slot order exact) */
void rw_le_rx_per(u32 chan)
{
    /* DWARF locals: u32 cmd@l1593, u32 exit@l1593, u32 value@l1593, u32 noise@l1593, u32 pwr_in_band@l1593, u32 pwr_full_band@l1593, u32 gain@l1593, u32 bchl@l1593, u32 bchh@l1593, u32 entry@l1593, u32[] gain_fcs@l1594, u32 fcs_i@l1595, u32 i@l1625, u32 total_p@l1628, u32 hec_ep@l1628, u32 rx_status@l1628 */
    u32 cmd, exit, value, noise, pwr_in_band, pwr_full_band, gain, bchl, bchh, entry;
    u32 gain_fcs[8];
    u32 fcs_i, i, total_p, hec_ep, rx_status, cp, crc_ep, type_ep, len_ep;
    u32 fifo_ovfl_ep, fec13_ep, fec_ep, fec23_ep, mic_ep, lt_ep, seq_ep, guard_ep;
    u32 default_ep, len_max_ep, pwr_r_error, pwr_d_error;
    u32 rxlinklbl, rxpriverr, rxtimeerr, rxbdmatch, rxnesnerr, rxsnerr;
    u32 rxmicerr, rxcrcerr, rxlenerr, rxtyperr, rxsyncerr;
    s8 rxrssi;
    u32 v;
    int k;
    REG_WRITE(0x3ff51098u, REG_READ(0x3ff51098u) | 0xc0000000u);
    rw_le_core_off();
    rw_init_em_radio_table();
    rw_dm_activate();
    REG_WRITE(0x6003122cu, REG_READ(0x6003122cu) & 0xffffu);
    /* 16-word EM init: bit-expand 0xffff with 0x2000302/0. */
    v = 0xffffu;
    for (k = 0; k < 16; k++) {
        REG_WRITE(0x3ffb0000u + (u32)(k * 4), (v & 1u) ? 0x2000302u : 0u);
        v >>= 1;
    }
    REG_WRITE(0x60031224u, 0xdeadbeefu);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) & 0xffff0000u);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) | 0x10000u);
    REG_WRITE(0x600312a0u, (REG_READ(0x600312a0u) & 0xffffc000u) | 0x5dcu);
    REG_WRITE(0x60031200u, REG_READ(0x60031200u) | 0x40000u);
    /* LE CS: format=29, sync=0x71764129, crc=0x555555, no RAL/filtering,
     * ch=chan, hopint=11, fh=0, txpwr=0, rxwide=1, rxwinsz=0x3fff,
     * txdesc=0, maxevtime=0 (stack immediates verified). */
    rw_le_init_cs(29, 0x71764129u, 0x555555u, 0, 0, 0, 0, chan, 11, 0, 0, 1, 0x3fffu, 0, 0);
    REG_WRITE(0x3ffb02c0u, 0u);
    REG_WRITE(0x3ffb02c4u, 0u);
    REG_WRITE(0x3ffb02c8u, 0u);
    REG_WRITE(0x3ffb02c0u, (REG_READ(0x3ffb02c0u) & 0xffff8000u) | 0x2d0u);
    REG_WRITE(0x3ffb02c8u, (REG_READ(0x3ffb02c8u) & 0xffff0000u) | 0xb00u);
    REG_WRITE(0x3ffb02c8u, REG_READ(0x3ffb02c8u) | 0xc000000u);
    REG_WRITE(0x3ffb02d0u, 0u);
    REG_WRITE(0x3ffb02d4u, 0u);
    REG_WRITE(0x3ffb02d8u, 0u);
    REG_WRITE(0x3ffb02d0u, (REG_READ(0x3ffb02d0u) & 0xffff8000u) | 0x2c0u);
    REG_WRITE(0x3ffb02d8u, (REG_READ(0x3ffb02d8u) & 0xffff0000u) | 0xb00u);
    REG_WRITE(0x3ffb02d8u, REG_READ(0x3ffb02d8u) | 0xc000000u);
    REG_WRITE(0x6003122cu, (REG_READ(0x6003122cu) & 0xffff8000u) | 0x2d0u);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) & 0x7fffffffu);
    REG_WRITE(0x600312f0u, REG_READ(0x600312f0u) & 0x7fffffffu);
    REG_WRITE(0x600312e0u, REG_READ(0x600312e0u) | 0x8000000u);
    REG_WRITE(0x60031218u, REG_READ(0x60031218u) | 8u);
    rw_le_core_on();
    phy_printf("RW RX PER\n");   /* .rodata.str1.4+0x278 */
    cmd = exit = value = noise = pwr_in_band = pwr_full_band = gain = entry = 0;
    bchl = bchh = 0;
    total_p = hec_ep = rx_status = cp = crc_ep = type_ep = len_ep = 0;
    fifo_ovfl_ep = fec13_ep = fec_ep = fec23_ep = mic_ep = lt_ep = seq_ep = guard_ep = 0;
    default_ep = len_max_ep = pwr_r_error = pwr_d_error = 0;
    rxlinklbl = rxpriverr = rxtimeerr = rxbdmatch = rxnesnerr = rxsnerr = 0;
    rxmicerr = rxcrcerr = rxlenerr = rxtyperr = rxsyncerr = 0;
    rxrssi = 0;
    i = 0;
    for (k = 0; k < 8; k++)
        gain_fcs[k] = 0;
    fcs_i = 0;
    exit = 0;
    ets_delay_us(20);
poll:
    rw_bb_rx_refesh();
    v = GetStopCmd();
    if (v == 3 || v == 0) {
        /* Latch exit; kick the LE engine once more. */
        exit = 1;
        REG_WRITE(0x60031200u, REG_READ(0x60031200u) | 0x4000000u);
    }
    /* Wait until either RX descriptor reports ready (bit15). */
    if (!(REG_READ(0x3ffb02c0u) & 0x8000u) && !(REG_READ(0x3ffb02d0u) & 0x8000u))
        goto poll;
    if (REG_READ(0x3ffb02c0u) & 0x8000u) {
        rw_le_rxstat_unpack(0x3ffb02c0u, &rxlinklbl, &rxpriverr, &rxtimeerr,
                            &rxbdmatch, &rxnesnerr, &rxsnerr, &rxmicerr,
                            &rxcrcerr, &rxlenerr, &rxtyperr, &rxsyncerr, &rxrssi);
        REG_WRITE(0x3ffb02c0u, REG_READ(0x3ffb02c0u) & 0xffff7fffu);
    }
    if (REG_READ(0x3ffb02d0u) & 0x8000u) {
        rw_le_rxstat_unpack(0x3ffb02d0u, &rxlinklbl, &rxpriverr, &rxtimeerr,
                            &rxbdmatch, &rxnesnerr, &rxsnerr, &rxmicerr,
                            &rxcrcerr, &rxlenerr, &rxtyperr, &rxsyncerr, &rxrssi);
        REG_WRITE(0x3ffb02d0u, REG_READ(0x3ffb02d0u) & 0xffff7fffu);
    }
    /* Error-class ladder over the unpacked flags (name routing approx). */
    if (rxlenerr) {
        goto poll;
    } else if (rxtyperr) {
        total_p++;
    } else if (rxsyncerr) {
        hec_ep++;
    } else if (rxcrcerr) {
        rx_status++;
    } else if (rxsnerr) {
        cp++;
    } else if (rxnesnerr) {
        crc_ep++;
    } else if (rxtimeerr) {
        type_ep++;
    } else if (rxpriverr) {
        len_ep++;
    } else {
        default_ep++;
    }
    /* Gain/power accumulate from 0x3ff51050/74/78. */
    v = REG_READ(0x3ff51050u);
    {
        u32 g74 = REG_READ(0x3ff51074u);
        u32 g78 = REG_READ(0x3ff51078u);
        len_max_ep = (v >> 6) & 1u;
        pwr_r_error = (v >> 5) & 1u;
        pwr_d_error = (v >> 4) & 1u;
        fifo_ovfl_ep = g78;
        pwr_in_band += 0x100u - (g74 & 0xffu);
        pwr_full_band += 0x100u - ((g78 >> 24) & 0xffu);
        gain += (g78 >> 16) & 0xffu;
        i++;
        value += 0u + ((v >> 2) & 1u);
        noise += v & 1u;
        entry += (v >> 7) & 1u;
        cmd += (v >> 3) & 1u;
    }
    /* TX-ready gate: re-poll until 0x60031214 bit3, then re-arm. */
    if (!(REG_READ(0x60031214u) & 8u))
        goto poll;
    REG_WRITE(0x60031218u, REG_READ(0x60031218u) | 8u);
    for (k = 0; k < 16; k++)
        REG_WRITE(0x3ffb0000u + (u32)(k * 4),
                  REG_READ(0x3ffb0000u + (u32)(k * 4)) & 0xffffffcfu);
    if (!exit)
        goto poll;
    rw_le_core_off();
    /* Exact 21-lane format .rodata.str1.4+0x284:
     * "%x %x %x %x %x %x %x %x %x %x w %x %x %x %x %x %x %x %x p %x %x %x\n".
     * Slot order exact; name routing approximate except i. */
    phy_printf("%x %x %x %x %x %x %x %x %x %x w %x %x %x %x %x %x %x %x p %x %x %x\n",
               i, default_ep, total_p, hec_ep, rx_status, fifo_ovfl_ep,
               cp, crc_ep, type_ep, len_ep, mic_ep, lt_ep, seq_ep, guard_ep,
               fec_ep, fec23_ep, fec13_ep, pwr_r_error, pwr_d_error, value, noise);
}

/* rw_le_rx_per_init bt_rw_le_testmode.c:2067 @ bt_rw_le_testmode.o size 466B [dwarf-sig]
 * Calls: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_init_cs, rw_le_core_on | Data refs: .rodata.str1.4, phy_printf, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_init_cs | MMIO: 0x3ff51098, 0x3ffb0000, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031200, 0x60031218, 0x60031224, 0x60031228, 0x6003122c, 0x600312a0, 0x600312e0, 0x600312f0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rx_per_init(u32 chan)
{
    (void)chan;
    /* DWARF locals: u32 cmd@l2068, u32 exit@l2068, u32 value@l2068, u32 noise@l2068, u32 pwr_in_band@l2068, u32 pwr_full_band@l2068, u32 gain@l2068, u32 bchl@l2068, u32 bchh@l2068, u32 entry@l2068, u32[] gain_fcs@l2069, u32 fcs_i@l2070, u32 i@l2100, u32 total_p@l2103, u32 hec_ep@l2103, u32 rx_status@l2103 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rx_per_init> (176 insns) + DWARF line rows for bt_rw_le_testmode.c:2067.
     * Ordered callee relocs: phy_printf, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_init_cs, rw_le_core_on.
     */
}

/* rw_le_rx_per_syncw bt_rw_le_testmode.c:1750 @ bt_rw_le_testmode.o size 1451B [dwarf-sig]
 * Calls: rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_init_cs, rw_le_core_on, phy_printf, ets_delay_us, rw_bb_rx_refesh, GetStopCmd, rw_le_rxstat_unpack, get_bt_rx_rssi | Data refs: .rodata.str1.4, GetStopCmd, esp_rx_result, esp_rx_valid, ets_delay_us, get_bt_rx_rssi, phy_printf, rw_bb_rx_refesh, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_init_cs, rw_le_rxstat_unpack, short_log_en | MMIO: 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ff51098, 0x3ffb0000, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031200, 0x60031214, 0x60031218, 0x60031224, 0x60031228, 0x6003122c, 0x600312a0, 0x600312e0, 0x600312f0
 * Fidelity: medium - rw_le_rx_per skeleton with sync-word init, RSSI result
 *   publish (esp_rx_result/esp_rx_valid), conditional "rx_num/rx_rssi" print
 *   and shared 21-lane summary verified; counter-name routing approximate */
void rw_le_rx_per_syncw(u32 chan, u32 syncw)
{
    /* DWARF locals: u32 cmd@l1751, u32 exit@l1751, u32 value@l1751, u32 noise@l1751, u32 pwr_in_band@l1751, u32 pwr_full_band@l1751, u32 gain@l1751, u32 bchl@l1751, u32 bchh@l1751, u32 entry@l1751, u32[] gain_fcs@l1752, u32 fcs_i@l1753, s32 avg_rssi@l1754, u32 i@l1783, u32 total_p@l1786, u32 hec_ep@l1786 */
    extern u32 esp_rx_result, esp_rx_valid;
    extern u8 short_log_en;
    u32 cmd, exit, value, noise, pwr_in_band, pwr_full_band, gain, bchl, bchh, entry;
    u32 gain_fcs[8];
    u32 fcs_i, i, total_p, hec_ep, rx_status, cp, crc_ep, type_ep, len_ep;
    u32 fifo_ovfl_ep, fec13_ep, fec_ep, fec23_ep, mic_ep, lt_ep, seq_ep, guard_ep;
    u32 default_ep, len_max_ep, pwr_r_error, pwr_d_error;
    u32 rxlinklbl, rxpriverr, rxtimeerr, rxbdmatch, rxnesnerr, rxsnerr;
    u32 rxmicerr, rxcrcerr, rxlenerr, rxtyperr, rxsyncerr;
    s8 rxrssi;
    s32 avg_rssi;
    u32 v;
    int k;
    REG_WRITE(0x3ff51098u, REG_READ(0x3ff51098u) | 0xc0000000u);
    rw_le_core_off();
    rw_init_em_radio_table();
    rw_dm_activate();
    REG_WRITE(0x6003122cu, REG_READ(0x6003122cu) & 0xffffu);
    v = 0xffffu;
    for (k = 0; k < 16; k++) {
        REG_WRITE(0x3ffb0000u + (u32)(k * 4), (v & 1u) ? 0x2000302u : 0u);
        v >>= 1;
    }
    REG_WRITE(0x60031224u, 0xdeadbeefu);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) & 0xffff0000u);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) | 0x10000u);
    REG_WRITE(0x600312a0u, (REG_READ(0x600312a0u) & 0xffffc000u) | 0x5dcu);
    REG_WRITE(0x60031200u, REG_READ(0x60031200u) | 0x40000u);
    /* Sync-word variant: sync comes from the syncw param. */
    rw_le_init_cs(29, syncw, 0x555555u, 0, 0, 0, 0, chan, 11, 0, 0, 1, 0x3fffu, 0, 0);
    REG_WRITE(0x3ffb02c0u, 0u);
    REG_WRITE(0x3ffb02c4u, 0u);
    REG_WRITE(0x3ffb02c8u, 0u);
    REG_WRITE(0x3ffb02c0u, (REG_READ(0x3ffb02c0u) & 0xffff8000u) | 0x2d0u);
    REG_WRITE(0x3ffb02c8u, (REG_READ(0x3ffb02c8u) & 0xffff0000u) | 0xb00u);
    REG_WRITE(0x3ffb02c8u, REG_READ(0x3ffb02c8u) | 0xc000000u);
    REG_WRITE(0x3ffb02d0u, 0u);
    REG_WRITE(0x3ffb02d4u, 0u);
    REG_WRITE(0x3ffb02d8u, 0u);
    REG_WRITE(0x3ffb02d0u, (REG_READ(0x3ffb02d0u) & 0xffff8000u) | 0x2c0u);
    REG_WRITE(0x3ffb02d8u, (REG_READ(0x3ffb02d8u) & 0xffff0000u) | 0xb00u);
    REG_WRITE(0x3ffb02d8u, REG_READ(0x3ffb02d8u) | 0xc000000u);
    REG_WRITE(0x6003122cu, (REG_READ(0x6003122cu) & 0xffff8000u) | 0x2d0u);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) & 0x7fffffffu);
    REG_WRITE(0x600312f0u, REG_READ(0x600312f0u) & 0x7fffffffu);
    REG_WRITE(0x600312e0u, REG_READ(0x600312e0u) | 0x8000000u);
    REG_WRITE(0x60031218u, REG_READ(0x60031218u) | 8u);
    rw_le_core_on();
    phy_printf("RW RX PER\n");   /* .rodata.str1.4+0x278 */
    cmd = exit = value = noise = pwr_in_band = pwr_full_band = gain = entry = 0;
    bchl = bchh = 0;
    total_p = hec_ep = rx_status = cp = crc_ep = type_ep = len_ep = 0;
    fifo_ovfl_ep = fec13_ep = fec_ep = fec23_ep = mic_ep = lt_ep = seq_ep = guard_ep = 0;
    default_ep = len_max_ep = pwr_r_error = pwr_d_error = 0;
    rxlinklbl = rxpriverr = rxtimeerr = rxbdmatch = rxnesnerr = rxsnerr = 0;
    rxmicerr = rxcrcerr = rxlenerr = rxtyperr = rxsyncerr = 0;
    rxrssi = 0;
    avg_rssi = 0;
    i = 0;
    for (k = 0; k < 8; k++)
        gain_fcs[k] = 0;
    fcs_i = 0;
    exit = 0;
    ets_delay_us(20);
poll:
    rw_bb_rx_refesh();
    v = GetStopCmd();
    if (v == 3 || v == 0) {
        exit = 1;
        REG_WRITE(0x60031200u, REG_READ(0x60031200u) | 0x4000000u);
    }
    if (!(REG_READ(0x3ffb02c0u) & 0x8000u) && !(REG_READ(0x3ffb02d0u) & 0x8000u))
        goto poll;
    if (REG_READ(0x3ffb02c0u) & 0x8000u) {
        rw_le_rxstat_unpack(0x3ffb02c0u, &rxlinklbl, &rxpriverr, &rxtimeerr,
                            &rxbdmatch, &rxnesnerr, &rxsnerr, &rxmicerr,
                            &rxcrcerr, &rxlenerr, &rxtyperr, &rxsyncerr, &rxrssi);
        REG_WRITE(0x3ffb02c0u, REG_READ(0x3ffb02c0u) & 0xffff7fffu);
    }
    if (REG_READ(0x3ffb02d0u) & 0x8000u) {
        rw_le_rxstat_unpack(0x3ffb02d0u, &rxlinklbl, &rxpriverr, &rxtimeerr,
                            &rxbdmatch, &rxnesnerr, &rxsnerr, &rxmicerr,
                            &rxcrcerr, &rxlenerr, &rxtyperr, &rxsyncerr, &rxrssi);
        REG_WRITE(0x3ffb02d0u, REG_READ(0x3ffb02d0u) & 0xffff7fffu);
    }
    if (rxlenerr) {
        goto poll;
    } else if (rxtyperr) {
        total_p++;
    } else if (rxsyncerr) {
        hec_ep++;
    } else if (rxcrcerr) {
        rx_status++;
    } else if (rxsnerr) {
        cp++;
    } else if (rxnesnerr) {
        crc_ep++;
    } else if (rxtimeerr) {
        type_ep++;
    } else if (rxpriverr) {
        len_ep++;
    } else {
        default_ep++;
    }
    v = REG_READ(0x3ff51050u);
    {
        u32 g74 = REG_READ(0x3ff51074u);
        u32 g78 = REG_READ(0x3ff51078u);
        len_max_ep = (v >> 6) & 1u;
        pwr_r_error = (v >> 5) & 1u;
        pwr_d_error = (v >> 4) & 1u;
        fifo_ovfl_ep = g78;
        pwr_in_band += 0x100u - (g74 & 0xffu);
        pwr_full_band += 0x100u - ((g78 >> 24) & 0xffu);
        gain += (g78 >> 16) & 0xffu;
        i++;
        value += (v >> 2) & 1u;
        noise += v & 1u;
        entry += (v >> 7) & 1u;
        cmd += (v >> 3) & 1u;
        avg_rssi += rxrssi;
    }
    if (!(REG_READ(0x60031214u) & 8u))
        goto poll;
    REG_WRITE(0x60031218u, REG_READ(0x60031218u) | 8u);
    for (k = 0; k < 16; k++)
        REG_WRITE(0x3ffb0000u + (u32)(k * 4),
                  REG_READ(0x3ffb0000u + (u32)(k * 4)) & 0xffffffcfu);
    if (!exit)
        goto poll;
    rw_le_core_off();
    get_bt_rx_rssi(&pwr_in_band, &gain, &pwr_full_band, total_p);
    /* Publish LE RX results, then the conditional count/RSSI line. */
    esp_rx_valid = 0;
    {
        u32 *rp = &esp_rx_result;
        rp[0] = i;
        rp[1] = gain;
        rp[2] = total_p;
    }
    if (short_log_en)
        phy_printf("rx_num: %d rx_rssi: %d\n", i, avg_rssi);
    phy_printf("%x %x %x %x %x %x %x %x %x %x w %x %x %x %x %x %x %x %x p %x %x %x\n",
               i, default_ep, total_p, hec_ep, rx_status, fifo_ovfl_ep,
               cp, crc_ep, type_ep, len_ep, mic_ep, lt_ep, seq_ep, guard_ep,
               fec_ep, fec23_ep, fec13_ep, pwr_r_error, pwr_d_error, value, noise);
}

/* rw_le_rx_per_syncw_polling bt_rw_le_testmode.c:2237 @ bt_rw_le_testmode.o size 30B [dwarf-sig]
 * Calls: rw_le_rx_per_init, cmd_polling_attach | Data refs: cmd_polling_attach, rw_le_rx_per_init, rw_le_rx_per_syncw_service_polling | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rx_per_syncw_polling(u32 chan)
{
    (void)chan;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rx_per_syncw_polling> (11 insns) + DWARF line rows for bt_rw_le_testmode.c:2237.
     * Ordered callee relocs: rw_le_rx_per_init, cmd_polling_attach.
     */
}

/* rw_le_rx_per_syncw_polling_stop bt_rw_le_testmode.c:2244 @ bt_rw_le_testmode.o size 180B [dwarf-sig]
 * Calls: cmd_polling_dettach, rw_le_core_off, phy_printf | Data refs: .rodata.str1.4, cmd_polling_dettach, cp_polling, crc_ep_polling, len_ep_polling, mic_ep_polling, nesn_ep_polling, phy_printf, priv_ep_polling, rw_le_core_off, rw_le_rx_per_syncw_service_polling, sn_ep_polling, time_ep_polling, total_fullband_polling, total_gain_polling, total_inband_polling, total_p_polling, total_rssi_polling, type_ep_polling | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rx_per_syncw_polling_stop(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rx_per_syncw_polling_stop> (74 insns) + DWARF line rows for bt_rw_le_testmode.c:2244.
     * Ordered callee relocs: cmd_polling_dettach, rw_le_core_off, phy_printf.
     */
}

/* rw_le_rx_per_syncw_rssi bt_rw_le_testmode.c:1901 @ bt_rw_le_testmode.o size 1566B [dwarf-sig]
 * Calls: rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_init_cs, rw_le_core_on, phy_printf, ets_delay_us, rw_bb_rx_refesh, GetStopCmd, rw_le_rxstat_unpack, get_bt_rx_rssi | Data refs: .rodata.str1.4, GetStopCmd, ets_delay_us, get_bt_rx_rssi, phy_printf, rw_bb_rx_refesh, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_init_cs, rw_le_rxstat_unpack | MMIO: 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ff51098, 0x3ffb0000, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x60031200, 0x60031214, 0x60031218, 0x60031224, 0x60031228, 0x6003122c, 0x600312a0, 0x600312e0, 0x600312f0
 * Fidelity: medium - rw_le_rx_per_syncw skeleton; RSSI epilogue
 *   (get_bt_rx_rssi into shifted lanes, sign-extended RSSI "r" lanes,
 *   25-lane summary format) verified; counter-name routing approximate */
void rw_le_rx_per_syncw_rssi(u32 chan, u32 syncw)
{
    /* DWARF locals: u32 cmd@l1902, u32 exit@l1902, u32 value@l1902, u32 noise@l1902, u32 pwr_in_band@l1902, u32 pwr_full_band@l1902, u32 gain@l1902, u32 bchl@l1902, u32 bchh@l1902, u32 entry@l1902, u32[] gain_fcs@l1903, u32 fcs_i@l1904, u32 i@l1934, u32 total_p@l1937, u32 hec_ep@l1937, u32 rx_status@l1937 */
    u32 cmd, exit, value, noise, pwr_in_band, pwr_full_band, gain, bchl, bchh, entry;
    u32 gain_fcs[8];
    u32 fcs_i, i, total_p, hec_ep, rx_status, cp, crc_ep, type_ep, len_ep;
    u32 fifo_ovfl_ep, fec13_ep, fec_ep, fec23_ep, mic_ep, lt_ep, seq_ep, guard_ep;
    u32 default_ep, len_max_ep, pwr_r_error, pwr_d_error;
    u32 rxlinklbl, rxpriverr, rxtimeerr, rxbdmatch, rxnesnerr, rxsnerr;
    u32 rxmicerr, rxcrcerr, rxlenerr, rxtyperr, rxsyncerr;
    s8 rxrssi;
    s32 rssi0, rssi1, rssi2, rssi3;
    u32 v;
    int k;
    REG_WRITE(0x3ff51098u, REG_READ(0x3ff51098u) | 0xc0000000u);
    rw_le_core_off();
    rw_init_em_radio_table();
    rw_dm_activate();
    REG_WRITE(0x6003122cu, REG_READ(0x6003122cu) & 0xffffu);
    v = 0xffffu;
    for (k = 0; k < 16; k++) {
        REG_WRITE(0x3ffb0000u + (u32)(k * 4), (v & 1u) ? 0x2000302u : 0u);
        v >>= 1;
    }
    REG_WRITE(0x60031224u, 0xdeadbeefu);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) & 0xffff0000u);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) | 0x10000u);
    REG_WRITE(0x600312a0u, (REG_READ(0x600312a0u) & 0xffffc000u) | 0x5dcu);
    REG_WRITE(0x60031200u, REG_READ(0x60031200u) | 0x40000u);
    rw_le_init_cs(29, syncw, 0x555555u, 0, 0, 0, 0, chan, 11, 0, 0, 1, 0x3fffu, 0, 0);
    REG_WRITE(0x3ffb02c0u, 0u);
    REG_WRITE(0x3ffb02c4u, 0u);
    REG_WRITE(0x3ffb02c8u, 0u);
    REG_WRITE(0x3ffb02c0u, (REG_READ(0x3ffb02c0u) & 0xffff8000u) | 0x2d0u);
    REG_WRITE(0x3ffb02c8u, (REG_READ(0x3ffb02c8u) & 0xffff0000u) | 0xb00u);
    REG_WRITE(0x3ffb02c8u, REG_READ(0x3ffb02c8u) | 0xc000000u);
    REG_WRITE(0x3ffb02d0u, 0u);
    REG_WRITE(0x3ffb02d4u, 0u);
    REG_WRITE(0x3ffb02d8u, 0u);
    REG_WRITE(0x3ffb02d0u, (REG_READ(0x3ffb02d0u) & 0xffff8000u) | 0x2c0u);
    REG_WRITE(0x3ffb02d8u, (REG_READ(0x3ffb02d8u) & 0xffff0000u) | 0xb00u);
    REG_WRITE(0x3ffb02d8u, REG_READ(0x3ffb02d8u) | 0xc000000u);
    REG_WRITE(0x6003122cu, (REG_READ(0x6003122cu) & 0xffff8000u) | 0x2d0u);
    REG_WRITE(0x60031228u, REG_READ(0x60031228u) & 0x7fffffffu);
    REG_WRITE(0x600312f0u, REG_READ(0x600312f0u) & 0x7fffffffu);
    REG_WRITE(0x600312e0u, REG_READ(0x600312e0u) | 0x8000000u);
    REG_WRITE(0x60031218u, REG_READ(0x60031218u) | 8u);
    rw_le_core_on();
    phy_printf("RW RX PER\n");   /* .rodata.str1.4+0x278 */
    cmd = exit = value = noise = pwr_in_band = pwr_full_band = gain = entry = 0;
    bchl = bchh = 0;
    total_p = hec_ep = rx_status = cp = crc_ep = type_ep = len_ep = 0;
    fifo_ovfl_ep = fec13_ep = fec_ep = fec23_ep = mic_ep = lt_ep = seq_ep = guard_ep = 0;
    default_ep = len_max_ep = pwr_r_error = pwr_d_error = 0;
    rxlinklbl = rxpriverr = rxtimeerr = rxbdmatch = rxnesnerr = rxsnerr = 0;
    rxmicerr = rxcrcerr = rxlenerr = rxtyperr = rxsyncerr = 0;
    rxrssi = 0;
    rssi0 = rssi1 = rssi2 = rssi3 = 0;
    i = 0;
    for (k = 0; k < 8; k++)
        gain_fcs[k] = 0;
    fcs_i = 0;
    exit = 0;
    ets_delay_us(20);
poll:
    rw_bb_rx_refesh();
    v = GetStopCmd();
    if (v == 3 || v == 0) {
        exit = 1;
        REG_WRITE(0x60031200u, REG_READ(0x60031200u) | 0x4000000u);
    }
    if (!(REG_READ(0x3ffb02c0u) & 0x8000u) && !(REG_READ(0x3ffb02d0u) & 0x8000u))
        goto poll;
    if (REG_READ(0x3ffb02c0u) & 0x8000u) {
        rw_le_rxstat_unpack(0x3ffb02c0u, &rxlinklbl, &rxpriverr, &rxtimeerr,
                            &rxbdmatch, &rxnesnerr, &rxsnerr, &rxmicerr,
                            &rxcrcerr, &rxlenerr, &rxtyperr, &rxsyncerr, &rxrssi);
        REG_WRITE(0x3ffb02c0u, REG_READ(0x3ffb02c0u) & 0xffff7fffu);
    }
    if (REG_READ(0x3ffb02d0u) & 0x8000u) {
        rw_le_rxstat_unpack(0x3ffb02d0u, &rxlinklbl, &rxpriverr, &rxtimeerr,
                            &rxbdmatch, &rxnesnerr, &rxsnerr, &rxmicerr,
                            &rxcrcerr, &rxlenerr, &rxtyperr, &rxsyncerr, &rxrssi);
        REG_WRITE(0x3ffb02d0u, REG_READ(0x3ffb02d0u) & 0xffff7fffu);
    }
    if (rxlenerr) {
        goto poll;
    } else if (rxtyperr) {
        total_p++;
    } else if (rxsyncerr) {
        hec_ep++;
    } else if (rxcrcerr) {
        rx_status++;
    } else if (rxsnerr) {
        cp++;
    } else if (rxnesnerr) {
        crc_ep++;
    } else if (rxtimeerr) {
        type_ep++;
    } else if (rxpriverr) {
        len_ep++;
    } else {
        default_ep++;
    }
    v = REG_READ(0x3ff51050u);
    {
        u32 g74 = REG_READ(0x3ff51074u);
        u32 g78 = REG_READ(0x3ff51078u);
        len_max_ep = (v >> 6) & 1u;
        pwr_r_error = (v >> 5) & 1u;
        pwr_d_error = (v >> 4) & 1u;
        fifo_ovfl_ep = g78;
        pwr_in_band += 0x100u - (g74 & 0xffu);
        pwr_full_band += 0x100u - ((g78 >> 24) & 0xffu);
        gain += (g78 >> 16) & 0xffu;
        i++;
        value += (v >> 2) & 1u;
        noise += v & 1u;
        entry += (v >> 7) & 1u;
        cmd += (v >> 3) & 1u;
    }
    if (!(REG_READ(0x60031214u) & 8u))
        goto poll;
    REG_WRITE(0x60031218u, REG_READ(0x60031218u) | 8u);
    for (k = 0; k < 16; k++)
        REG_WRITE(0x3ffb0000u + (u32)(k * 4),
                  REG_READ(0x3ffb0000u + (u32)(k * 4)) & 0xffffffcfu);
    if (!exit)
        goto poll;
    rw_le_core_off();
    get_bt_rx_rssi(&pwr_in_band, &gain, &pwr_full_band, total_p);
    /* Sign-extended RSSI lanes for the trailing "r %d %d %d %d". */
    rssi0 = (s32)(s8)(pwr_in_band & 0xffu);
    rssi1 = (s32)(s8)(pwr_full_band & 0xffu);
    rssi2 = (s32)(s8)(gain & 0xffu);
    rssi3 = (s32)(s8)(total_p & 0xffu);
    /* Exact 25-lane format .rodata.str1.4+0x2e0:
     * "%x %x %x %x %x %x %x %x %x %x w %x %x %x %x %x %x %x %x p %x %x %x r %d %d %d %d\n" */
    phy_printf("%x %x %x %x %x %x %x %x %x %x w %x %x %x %x %x %x %x %x p %x %x %x r %d %d %d %d\n",
               i, default_ep, total_p, hec_ep, rx_status, fifo_ovfl_ep,
               cp, crc_ep, type_ep, len_ep, mic_ep, lt_ep, seq_ep, guard_ep,
               fec_ep, fec23_ep, fec13_ep, pwr_r_error, pwr_d_error, value, noise,
               rssi0, rssi1, rssi2, rssi3);
}

/* rw_le_rx_per_syncw_service_polling bt_rw_le_testmode.c:2124 @ bt_rw_le_testmode.o size 722B [dwarf-sig]
 * Calls: rw_le_error_print, rw_bb_rx_refesh, rw_le_rxstat_unpack | Data refs: cp_polling, crc_ep_polling, len_ep_polling, mic_ep_polling, nesn_ep_polling, priv_ep_polling, rw_bb_rx_refesh, rw_le_error_print, rw_le_rxstat_unpack, sn_ep_polling, time_ep_polling, total_fullband_polling, total_gain_polling, total_inband_polling, total_p_polling, total_rssi_polling, type_ep_polling | MMIO: 0x3ff51074, 0x3ff51078, 0x3ffb02c0, 0x3ffb02d0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rx_per_syncw_service_polling(void)
{
    /* DWARF locals: u32 i@l2125, u32 clkn@l2125, u32 rawstp@l2125, u32 cmd@l2125, u32 exit@l2125, u32 count@l2125, u32 to@l2125, u32 gain_record_start@l2125, u32 rw_rxlinklbl@l2126, u32 rw_rxeirstat@l2126, u32 rw_rxguarderr@l2126, u32 rw_rxbadlt@l2126, u32 rw_rxfecerr@l2126, u32 rw_rxseqerr@l2126, u32 rw_rxmicerr@l2126, u32 rw_rxcrcerr@l2127 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rx_per_syncw_service_polling> (290 insns) + DWARF line rows for bt_rw_le_testmode.c:2124.
     * Ordered callee relocs: rw_le_error_print, rw_bb_rx_refesh, rw_le_rxstat_unpack.
     */
}

/* rw_le_rx_status_print bt_rw_le_testmode.c:353 @ bt_rw_le_testmode.o size 56B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, le_rx_n, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rx_status_print(u32 desc_addr)
{
    (void)desc_addr;
    /* DWARF locals: u32 data@l354, s8 rssi@l355 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rx_status_print> (21 insns) + DWARF line rows for bt_rw_le_testmode.c:353.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_le_rxdone bt_rw_le_testmode.c:345 @ bt_rw_le_testmode.o size 19B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_le_rxdone(u32 desc_addr)
{
    (void)desc_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rxdone> (7 insns) + DWARF line rows for bt_rw_le_testmode.c:345.
     */
}

/* rw_le_rxstat_unpack bt_rw_le_testmode.c:325 @ bt_rw_le_testmode.o size 105B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rxstat_unpack(u32 desc_addr, u32 * rxlinklbl, u32 * rxpriverr, u32 * rxtimeerr, u32 * rxbdaddrmatch, u32 * rxnesnerr, u32 * rxsnerr, u32 * rxmicerr, u32 * rxcrcerr, u32 * rxlenerr, u32 * rxtyperr, u32 * rxsyncerr, s8 * rxrssi)
{
    (void)desc_addr;
    (void)rxlinklbl;
    (void)rxpriverr;
    (void)rxtimeerr;
    (void)rxbdaddrmatch;
    (void)rxnesnerr;
    (void)rxsnerr;
    (void)rxmicerr;
    (void)rxcrcerr;
    (void)rxlenerr;
    (void)rxtyperr;
    (void)rxsyncerr;
    (void)rxrssi;
    /* DWARF locals: u32 localVal@l329 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rxstat_unpack> (42 insns) + DWARF line rows for bt_rw_le_testmode.c:325.
     */
}

/* rw_le_rxundone bt_rw_le_testmode.c:348 @ bt_rw_le_testmode.o size 21B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rxundone(u32 desc_addr)
{
    (void)desc_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_rxundone> (8 insns) + DWARF line rows for bt_rw_le_testmode.c:348.
     */
}

/* rw_le_scan_print bt_rw_le_testmode.c:366 @ bt_rw_le_testmode.o size 102B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ffb0000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_le_scan_print(u32 desc_addr, u32 filter, u32 rx_adva)
{
    (void)desc_addr;
    (void)filter;
    (void)rx_adva;
    /* DWARF locals: u32 data@l367, u32 buff_ptr@l368, u32 adva@l369, u32 count@l370, s8 rssi@l371 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_scan_print> (37 insns) + DWARF line rows for bt_rw_le_testmode.c:366.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_le_scan_refresh bt_rw_le_testmode.c:418 @ bt_rw_le_testmode.o size 26B [dwarf-sig-decl]
 * Calls: .text.rw_le_scan_refresh$part$1+0x44 | Data refs: (none) | MMIO: 0x60031214
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_scan_refresh(u32 txdesc_refresh, u32 winsz)
{
    (void)txdesc_refresh;
    (void)winsz;
    /* DWARF locals: u32 entry@l419, u32 i@l420, u32 data@l421, u32 chn@l422, u32 winsznow@l423 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_scan_refresh> (10 insns) + DWARF line rows for bt_rw_le_testmode.c:418.
     * Ordered callee relocs: .text.rw_le_scan_refresh$part$1+0x44.
     */
}

/* rw_le_scan_refresh$part$1 bt_rw_le_testmode.c:418 @ bt_rw_le_testmode.o size 282B [dwarf-sig-base-decl]
 * Calls: phy_printf | Data refs: .rodata.str1.4, evt_refresh_ind, last_scan_event_end, phy_printf, rw_scan_abort | MMIO: 0x3ffb0000, 0x3ffb0210, 0x3ffb0214, 0x3ffb02a0, 0x3ffb02b0, 0x60031218, 0x60031300, 0x60033d40
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_scan_refresh$part$1(u32 txdesc_refresh, u32 winsz)
{
    (void)txdesc_refresh;
    (void)winsz;
    /* DWARF locals: u32 entry@l419, u32 i@l420, u32 data@l421, u32 chn@l422, u32 winsznow@l423 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_scan_refresh$part$1> (106 insns) + DWARF line rows for bt_rw_le_testmode.c:418.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_le_set_current_rxdecriptor bt_rw_le_testmode.c:321 @ bt_rw_le_testmode.o size 30B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_set_current_rxdecriptor(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_set_current_rxdecriptor> (11 insns) + DWARF line rows for bt_rw_le_testmode.c:321.
     */
}

/* rw_le_set_dbaddr bt_rw_le_testmode.c:222 @ bt_rw_le_testmode.o size 38B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60031224, 0x60031228
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_set_dbaddr(u32 bdaddru, u32 bdaddrl)
{
    (void)bdaddru;
    (void)bdaddrl;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_set_dbaddr> (14 insns) + DWARF line rows for bt_rw_le_testmode.c:222.
     */
}

/* rw_le_test_init bt_rw_le_testmode.c:813 @ bt_rw_le_testmode.o size 157B [dwarf-sig]
 * Calls: rw_le_init_cs | Data refs: rw_le_init_cs | MMIO: 0x60031200, 0x60031224, 0x60031228, 0x600312a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_test_init(u32 tx_desc0, u32 tx_desc1, u32 format, u32 bdaddrl, u32 bdaddrh, u32 interval, u32 freq, u32 txpwr, u32 rxwide, u32 rxwinsz)
{
    (void)tx_desc0;
    (void)tx_desc1;
    (void)format;
    (void)bdaddrl;
    (void)bdaddrh;
    (void)interval;
    (void)freq;
    (void)txpwr;
    (void)rxwide;
    (void)rxwinsz;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_test_init> (60 insns) + DWARF line rows for bt_rw_le_testmode.c:813.
     * Ordered callee relocs: rw_le_init_cs.
     */
}

/* rw_le_tx bt_rw_le_testmode.c:969 @ bt_rw_le_testmode.o size 554B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, rw_le_error_print, .text.rw_evt_refresh$part$0+0x28, GetStopCmd | Data refs: .rodata.str1.4, GetStopCmd, PRBS9, evt_refresh_ind, phy_printf, prbs9_gen, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_error_print, rw_le_test_init | MMIO: 0x3ffb0000, 0x3ffb0210, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0300, 0x60031214, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_tx(u32 freqa, u32 freqb, u32 freqc, u32 txpwr, u32 mask)
{
    (void)freqa;
    (void)freqb;
    (void)freqc;
    (void)txpwr;
    (void)mask;
    /* DWARF locals: u32 freq@l970, u32 i@l970 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_tx> (205 insns) + DWARF line rows for bt_rw_le_testmode.c:969.
     * Ordered callee relocs: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, rw_le_error_print, .text.rw_evt_refresh$part$0+0x28, GetStopCmd.
     */
}

/* rw_le_tx_hoppe_syncw bt_rw_le_testmode.c:1182 @ bt_rw_le_testmode.o size 714B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, .text.rw_evt_refresh$part$0+0x28, GetStopCmd | Data refs: .rodata.str1.4, GetStopCmd, PRBS9, evt_refresh_ind, phy_printf, prbs9_gen, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_test_init | MMIO: 0x3ffb0000, 0x3ffb0204, 0x3ffb0208, 0x3ffb0210, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0300, 0x60031200, 0x60031214, 0x60031218, 0x6003122c, 0x600312e0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_tx_hoppe_syncw(u32 txpwr, u32 mask, u32 len, u32 data_type, u32 syncw)
{
    (void)txpwr;
    (void)mask;
    (void)len;
    (void)data_type;
    (void)syncw;
    /* DWARF locals: u32 i@l1183, u32 payload_data@l1183, u32 ch@l1184 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_tx_hoppe_syncw> (266 insns) + DWARF line rows for bt_rw_le_testmode.c:1182.
     * Ordered callee relocs: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, .text.rw_evt_refresh$part$0+0x28, GetStopCmd.
     */
}

/* rw_le_tx_nohoppe bt_rw_le_testmode.c:1024 @ bt_rw_le_testmode.o size 592B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, rw_txpwr_regulate, .text.rw_evt_refresh$part$0+0x28, rw_bb_tx_refesh, GetStopCmd | Data refs: .rodata.str1.4, GetStopCmd, PRBS9, bt_tx_num, phy_printf, prbs9_gen, rw_bb_tx_refesh, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_test_init, rw_txpwr_regulate | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0300, 0x60031214, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_tx_nohoppe(u32 freq, u32 txpwr, u32 mask, u32 len, u32 data_type, u32 tx_num_in)
{
    (void)freq;
    (void)txpwr;
    (void)mask;
    (void)len;
    (void)data_type;
    (void)tx_num_in;
    /* DWARF locals: u32 i@l1025, u32 bt_tx_num@l1066 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_tx_nohoppe> (216 insns) + DWARF line rows for bt_rw_le_testmode.c:1024.
     * Ordered callee relocs: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, rw_txpwr_regulate, .text.rw_evt_refresh$part$0+0x28, rw_bb_tx_refesh, GetStopCmd.
     */
}

/* rw_le_tx_nohoppe_init bt_rw_le_testmode.c:1278 @ bt_rw_le_testmode.o size 447B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on | Data refs: .rodata.str1.4, PRBS9, phy_printf, prbs9_gen, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_test_init | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0300, 0x60031218, 0x6003122c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_tx_nohoppe_init(u32 freq, u32 txpwr, u32 mask, u32 len)
{
    (void)freq;
    (void)txpwr;
    (void)mask;
    (void)len;
    /* DWARF locals: u32 i@l1279 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_tx_nohoppe_init> (166 insns) + DWARF line rows for bt_rw_le_testmode.c:1278.
     * Ordered callee relocs: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on.
     */
}

/* rw_le_tx_nohoppe_syncw bt_rw_le_testmode.c:1094 @ bt_rw_le_testmode.o size 676B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, rw_txpwr_regulate, .text.rw_evt_refresh$part$0+0x28, rw_bb_tx_refesh, GetStopCmd | Data refs: .rodata.str1.4, GetStopCmd, PRBS9, bt_tx_num, phy_printf, prbs9_gen, rw_bb_tx_refesh, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_le_test_init, rw_txpwr_regulate | MMIO: 0x3ffb0000, 0x3ffb0204, 0x3ffb0208, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0300, 0x60031214, 0x60031218, 0x6003122c, 0x600312e0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_tx_nohoppe_syncw(u32 freq, u32 txpwr, u32 mask, u32 len, u32 data_type, u32 syncw, u32 tx_num_in)
{
    (void)freq;
    (void)txpwr;
    (void)mask;
    (void)len;
    (void)data_type;
    (void)syncw;
    (void)tx_num_in;
    /* DWARF locals: u32 i@l1095, u32 payload_data@l1095, u32 bt_tx_num@l1150 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_tx_nohoppe_syncw> (249 insns) + DWARF line rows for bt_rw_le_testmode.c:1094.
     * Ordered callee relocs: phy_printf, prbs9_gen, rw_le_core_off, rw_init_em_radio_table, rw_dm_activate, rw_le_test_init, rw_le_core_on, rw_txpwr_regulate, .text.rw_evt_refresh$part$0+0x28, rw_bb_tx_refesh, GetStopCmd.
     */
}

/* rw_le_txpwr_toggle_test bt_rw_le_testmode.c:287 @ bt_rw_le_testmode.o size 55B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0210
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_txpwr_toggle_test(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_le_txpwr_toggle_test> (20 insns) + DWARF line rows for bt_rw_le_testmode.c:287.
     */
}

/* rw_pktcntl_fsm_print bt_rw_le_testmode.c:507 @ bt_rw_le_testmode.o size 179B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_pktcntl_fsm_print, .rodata.str1.4, phy_printf, pktcntl_fsm_data_last, pktcntl_fsm_print_start | MMIO: 0x60031250, 0x60031254
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_pktcntl_fsm_print(void)
{
    /* DWARF locals: u32 print@l508, u32 pktcntl_fsm_data@l511 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_le_testmode.rdis
     * function <rw_pktcntl_fsm_print> (64 insns) + DWARF line rows for bt_rw_le_testmode.c:507.
     * Ordered callee relocs: phy_printf.
     */
}

/* Undefined refs (22): GetStopCmd, PRBS9, bt_2480_opt_en, bt_rx_rssi, bt_tx_num, cmd_polling_attach, cmd_polling_dettach, esp_rx_result, esp_rx_valid, ets_delay_us, last_scan_event_end, phy_printf, prbs9_gen, rw_bb_rx_refesh, rw_bb_tx_refesh, rw_dm_activate, rw_init_em_radio_table, rw_le_core_off, rw_le_core_on, rw_scan_abort, rw_txpwr_regulate, short_log_en */