/* Reconstruction of bt_bb_common.o (libbttestmode.a)
 * CU: bt_bb_common.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 71 | funcdb functions: 43
 * Disasm: re/esp32-phy/disasm/libbttestmode/bt_bb_common.rdis
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

/* BT_fill_tx_buffer bt_bb_common.c:791 @ bt_bb_common.o size 95B [dwarf-sig-decl]
 * Calls: BT_fill_tx_buffer_1m_1010, BT_fill_tx_buffer_1m_0011, BT_fill_tx_buffer_1m_prbs9, BT_fill_tx_buffer_2m_1010, BT_fill_tx_buffer_2m_prbs9, BT_fill_tx_buffer_3m_1010, BT_fill_tx_buffer_3m_prbs9 | Data refs: BT_fill_tx_buffer_1m_0011, BT_fill_tx_buffer_1m_1010, BT_fill_tx_buffer_1m_prbs9, BT_fill_tx_buffer_2m_1010, BT_fill_tx_buffer_2m_prbs9, BT_fill_tx_buffer_3m_1010, BT_fill_tx_buffer_3m_prbs9 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer(uint32 data_rate, uint32 data_type)
{
    (void)data_rate;
    (void)data_type;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer> (32 insns) + DWARF line rows for bt_bb_common.c:791.
     * Ordered callee relocs: BT_fill_tx_buffer_1m_1010, BT_fill_tx_buffer_1m_0011, BT_fill_tx_buffer_1m_prbs9, BT_fill_tx_buffer_2m_1010, BT_fill_tx_buffer_2m_prbs9, BT_fill_tx_buffer_3m_1010, BT_fill_tx_buffer_3m_prbs9.
     */
}

/* BT_fill_tx_buffer_1m_0011 bt_bb_common.c:533 @ bt_bb_common.o size 64B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: 0x3ff51004, 0x3ff51010, 0x60012000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer_1m_0011(void)
{
    /* DWARF locals: uint32[] packet_1m@l534, int i@l536 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer_1m_0011> (25 insns) + DWARF line rows for bt_bb_common.c:533.
     * Ordered callee relocs: memcpy.
     */
}

/* BT_fill_tx_buffer_1m_1010 bt_bb_common.c:505 @ bt_bb_common.o size 64B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: 0x3ff51004, 0x3ff51010, 0x60012000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer_1m_1010(void)
{
    /* DWARF locals: U32[] packet_1m@l508, int i@l509 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer_1m_1010> (25 insns) + DWARF line rows for bt_bb_common.c:505.
     * Ordered callee relocs: memcpy.
     */
}

/* BT_fill_tx_buffer_1m_prbs9 bt_bb_common.c:547 @ bt_bb_common.o size 64B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: 0x3ff51004, 0x3ff51010, 0x60012000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer_1m_prbs9(void)
{
    /* DWARF locals: uint32[] packet_1m@l548, int i@l551 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer_1m_prbs9> (25 insns) + DWARF line rows for bt_bb_common.c:547.
     * Ordered callee relocs: memcpy.
     */
}

/* BT_fill_tx_buffer_2m_1010 bt_bb_common.c:561 @ bt_bb_common.o size 145B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51010, 0x60012000, 0x60012004, 0x60012008, 0x6001200c, 0x60012010, 0x60012014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer_2m_1010(void)
{
    /* DWARF locals: U32[] packet_1m@l563, int i@l564, U32[] packet_2m@l575 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer_2m_1010> (54 insns) + DWARF line rows for bt_bb_common.c:561.
     * Ordered callee relocs: memcpy.
     */
}

/* BT_fill_tx_buffer_2m_prbs9 bt_bb_common.c:608 @ bt_bb_common.o size 145B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51010, 0x60012000, 0x60012004, 0x60012008, 0x6001200c, 0x60012010, 0x60012014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer_2m_prbs9(void)
{
    /* DWARF locals: U32[] packet_1m@l610, int i@l611, U32[] packet_2m@l621 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer_2m_prbs9> (54 insns) + DWARF line rows for bt_bb_common.c:608.
     * Ordered callee relocs: memcpy.
     */
}

/* BT_fill_tx_buffer_3m_1010 bt_bb_common.c:630 @ bt_bb_common.o size 145B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51010, 0x60012000, 0x60012004, 0x60012008, 0x6001200c, 0x60012010, 0x60012014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer_3m_1010(void)
{
    /* DWARF locals: U32[] packet_1m@l632, int i@l633, U32[] packet_3m@l643 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer_3m_1010> (54 insns) + DWARF line rows for bt_bb_common.c:630.
     * Ordered callee relocs: memcpy.
     */
}

/* BT_fill_tx_buffer_3m_prbs9 bt_bb_common.c:676 @ bt_bb_common.o size 145B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51010, 0x60012000, 0x60012004, 0x60012008, 0x6001200c, 0x60012010, 0x60012014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_tx_buffer_3m_prbs9(void)
{
    /* DWARF locals: U32[] packet_1m@l678, int i@l679, U32[] packet_3m@l689 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_fill_tx_buffer_3m_prbs9> (54 insns) + DWARF line rows for bt_bb_common.c:676.
     * Ordered callee relocs: memcpy.
     */
}

/* BT_get_pwr bt_bb_common.c:1232 @ bt_bb_common.o size 288B [dwarf-sig]
 * Calls: ets_delay_us | Data refs: ets_delay_us | MMIO: 0x3ff51090, 0x60032100, 0x60032108, 0x60032120, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_get_pwr(u32 n, u32 * power_min, u32 * power_average, u32 * power_filted)
{
    (void)n;
    (void)power_min;
    (void)power_average;
    (void)power_filted;
    /* DWARF locals: u32 i@l1233, u32 rx_status@l1233, u32 sum_power@l1233, u32 pwr_now@l1233, u32 rdata@l1233, u32 end@l1233 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_get_pwr> (112 insns) + DWARF line rows for bt_bb_common.c:1232.
     * Ordered callee relocs: ets_delay_us.
     */
}

/* BT_mac_iqview_debug bt_bb_common.c:1041 @ bt_bb_common.o size 166B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320a8, 0x60032124, 0x600321b0, 0x600321b8, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_iqview_debug(u32 nowhite)
{
    (void)nowhite;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_mac_iqview_debug> (62 insns) + DWARF line rows for bt_bb_common.c:1041.
     */
}

/* BT_rx_start bt_bb_common.c:1056 @ bt_bb_common.o size 251B [dwarf-sig]
 * Calls: ets_delay_us, BT_mac_iqview_debug, BT_init_rx_filters, phy_printf | Data refs: .rodata.str1.4, BT_init_rx_filters, BT_mac_iqview_debug, ets_delay_us, phy_printf | MMIO: 0x3ff51018, 0x3ff5101c, 0x3ff51030, 0x3ff51038, 0x60012000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_start(uint16 data_rate, uint16 freq_offset_500k, uint16 start, uint16 bit_len, uint16 freq)
{
    (void)data_rate;
    (void)freq_offset_500k;
    (void)start;
    (void)bit_len;
    (void)freq;
    /* DWARF locals: int i@l1058 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_rx_start> (94 insns) + DWARF line rows for bt_bb_common.c:1056.
     * Ordered callee relocs: ets_delay_us, BT_mac_iqview_debug, BT_init_rx_filters, phy_printf.
     */
}

/* BT_set_tx_on_guard_time bt_bb_common.c:781 @ bt_bb_common.o size 16B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff5100c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_set_tx_on_guard_time(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_set_tx_on_guard_time> (6 insns) + DWARF line rows for bt_bb_common.c:781.
     */
}

/* BT_set_tx_on_guard_time_new bt_bb_common.c:785 @ bt_bb_common.o size 40B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff5100c, 0x3ff51044
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_set_tx_on_guard_time_new(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_set_tx_on_guard_time_new> (15 insns) + DWARF line rows for bt_bb_common.c:785.
     */
}

/* BT_start_tx bt_bb_common.c:769 @ bt_bb_common.o size 82B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx(uint32 data_rate, unsigned int freq_point)
{
    (void)data_rate;
    (void)freq_point;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx> (30 insns) + DWARF line rows for bt_bb_common.c:769.
     */
}

/* BT_start_tx_1m bt_bb_common.c:697 @ bt_bb_common.o size 24B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx_1m(unsigned int freq_point)
{
    (void)freq_point;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx_1m> (9 insns) + DWARF line rows for bt_bb_common.c:697.
     */
}

/* BT_start_tx_1m_new bt_bb_common.c:708 @ bt_bb_common.o size 42B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx_1m_new(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx_1m_new> (16 insns) + DWARF line rows for bt_bb_common.c:708.
     */
}

/* BT_start_tx_2m_3m bt_bb_common.c:717 @ bt_bb_common.o size 54B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx_2m_3m(unsigned int freq_point)
{
    (void)freq_point;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx_2m_3m> (20 insns) + DWARF line rows for bt_bb_common.c:717.
     */
}

/* BT_start_tx_2m_3m_new bt_bb_common.c:732 @ bt_bb_common.o size 72B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51014, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx_2m_3m_new(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx_2m_3m_new> (27 insns) + DWARF line rows for bt_bb_common.c:732.
     */
}

/* BT_start_tx_8m bt_bb_common.c:776 @ bt_bb_common.o size 118B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51014, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx_8m(uint32 data_rate)
{
    (void)data_rate;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx_8m> (44 insns) + DWARF line rows for bt_bb_common.c:776.
     */
}

/* BT_start_tx_packet bt_bb_common.c:823 @ bt_bb_common.o size 244B [dwarf-sig]
 * Calls: BT_start_tx, ets_delay_us | Data refs: BT_start_tx, ets_delay_us | MMIO: 0x3ff46090, 0x3ff51004, 0x3ff51008, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx_packet(uint16 tx_freq_offset_500k, uint32 data_rate, uint32 delay)
{
    (void)tx_freq_offset_500k;
    (void)data_rate;
    (void)delay;
    /* DWARF locals: int i@l825, int temp@l825 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx_packet> (88 insns) + DWARF line rows for bt_bb_common.c:823.
     * Ordered callee relocs: BT_start_tx, ets_delay_us.
     */
}

/* BT_start_tx_packet_8m bt_bb_common.c:845 @ bt_bb_common.o size 212B [dwarf-sig]
 * Calls: BT_tx_8m_enable, BT_start_tx_8m | Data refs: BT_start_tx_8m, BT_tx_8m_enable | MMIO: 0x3ff46090, 0x3ff51004, 0x3ff51008, 0x3ff51030, 0x3ff51038, 0x3ff51040, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_start_tx_packet_8m(uint16 tx_freq_offset_500k, uint32 data_rate, uint32 delay)
{
    (void)tx_freq_offset_500k;
    (void)data_rate;
    (void)delay;
    /* DWARF locals: int i@l847, int temp@l847 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_start_tx_packet_8m> (79 insns) + DWARF line rows for bt_bb_common.c:845.
     * Ordered callee relocs: BT_tx_8m_enable, BT_start_tx_8m.
     */
}

/* BT_tx_8m_disable bt_bb_common.c:501 @ bt_bb_common.o size 23B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51040
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_8m_disable(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_tx_8m_disable> (9 insns) + DWARF line rows for bt_bb_common.c:501.
     */
}

/* BT_tx_LE_en bt_bb_common.c:1141 @ bt_bb_common.o size 53B [dwarf-sig-decl]
 * Calls: .text.BT_tx_LE_en$part$4+0xc | Data refs: (none) | MMIO: 0x3ff51000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_LE_en(u32 enable)
{
    (void)enable;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_tx_LE_en> (19 insns) + DWARF line rows for bt_bb_common.c:1141.
     * Ordered callee relocs: .text.BT_tx_LE_en$part$4+0xc.
     */
}

/* BT_tx_LE_en$part$4 bt_bb_common.c:1141 @ bt_bb_common.o size 63B [dwarf-sig-base-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51000, 0x3ff51004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_LE_en$part$4(u32 enable)
{
    (void)enable;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_tx_LE_en$part$4> (24 insns) + DWARF line rows for bt_bb_common.c:1141.
     */
}

/* BT_tx_forever bt_bb_common.c:810 @ bt_bb_common.o size 77B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60002000, 0x60002004, 0x6000200c, 0x60002010, 0x60002018, 0x6000201c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_forever(uint16 tx_freq_offset_500k)
{
    (void)tx_freq_offset_500k;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_tx_forever> (29 insns) + DWARF line rows for bt_bb_common.c:810.
     */
}

/* BT_tx_packet bt_bb_common.c:868 @ bt_bb_common.o size 147B [dwarf-sig]
 * Calls: BT_fill_tx_buffer, BT_start_tx_packet, GetStopCmd | Data refs: BT_fill_tx_buffer, BT_start_tx_packet, GetStopCmd | MMIO: 0x3ff5100c, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_packet(uint16 freq_odd, uint16 freq_even, uint16 tx_freq_offset_500k, uint32 slot_time, uint32 delay, uint32 data_rate, uint32 data_type, uint32 tx_slot, uint32 tx_off_delay)
{
    (void)freq_odd;
    (void)freq_even;
    (void)tx_freq_offset_500k;
    (void)slot_time;
    (void)delay;
    (void)data_rate;
    (void)data_type;
    (void)tx_slot;
    (void)tx_off_delay;
    /* DWARF locals: uint32 time_now@l869, uint32 next_odd_slot@l871, uint32 next_even_slot@l872, uint32 next_tx@l873, uint32 odd@l875, int i@l876, int j@l876, sint16[] freq_offset_tab@l877, uint32 * chan_param@l879, uint32 * param_flag@l880 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_tx_packet> (57 insns) + DWARF line rows for bt_bb_common.c:868.
     * Ordered callee relocs: BT_fill_tx_buffer, BT_start_tx_packet, GetStopCmd.
     */
}

/* BT_tx_packet_8m bt_bb_common.c:913 @ bt_bb_common.o size 171B [dwarf-sig]
 * Calls: BT_fill_tx_buffer, BT_start_tx_packet_8m, GetStopCmd | Data refs: BT_fill_tx_buffer, BT_start_tx_packet_8m, GetStopCmd | MMIO: 0x3ff5100c, 0x3ff51044, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_packet_8m(uint16 freq_odd, uint16 freq_even, uint16 tx_freq_offset_500k, uint32 slot_time, uint32 delay, uint32 data_rate, uint32 data_type, uint32 tx_slot, uint32 tx_off_delay)
{
    (void)freq_odd;
    (void)freq_even;
    (void)tx_freq_offset_500k;
    (void)slot_time;
    (void)delay;
    (void)data_rate;
    (void)data_type;
    (void)tx_slot;
    (void)tx_off_delay;
    /* DWARF locals: uint32 time_now@l914, uint32 next_odd_slot@l916, uint32 next_even_slot@l917, uint32 next_tx@l918, uint32 odd@l920, int i@l921, int j@l921, sint16[] freq_offset_tab@l922, uint32 * chan_param@l924, uint32 * param_flag@l925 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_tx_packet_8m> (66 insns) + DWARF line rows for bt_bb_common.c:913.
     * Ordered callee relocs: BT_fill_tx_buffer, BT_start_tx_packet_8m, GetStopCmd.
     */
}

/* BT_wait4tx_end bt_bb_common.c:746 @ bt_bb_common.o size 62B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_wait4tx_end(unsigned int data_rate)
{
    (void)data_rate;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_wait4tx_end> (23 insns) + DWARF line rows for bt_bb_common.c:746.
     */
}

/* BT_wait4tx_end_new bt_bb_common.c:759 @ bt_bb_common.o size 74B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51008, 0x3ff51030, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_wait4tx_end_new(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <BT_wait4tx_end_new> (28 insns) + DWARF line rows for bt_bb_common.c:759.
     */
}

/* LE_fill_tx_PDU_byte bt_bb_common.c:1161 @ bt_bb_common.o size 63B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_fill_tx_PDU_byte(u32 nbyte, u32 data)
{
    (void)nbyte;
    (void)data;
    /* DWARF locals: u32 n@l1162, u32 word_offset@l1163, u32 byte_offset@l1164 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <LE_fill_tx_PDU_byte> (23 insns) + DWARF line rows for bt_bb_common.c:1161.
     */
}

/* LE_fill_tx_access_addr bt_bb_common.c:1154 @ bt_bb_common.o size 84B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60012000, 0x60012004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_fill_tx_access_addr(u32 ac)
{
    (void)ac;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <LE_fill_tx_access_addr> (31 insns) + DWARF line rows for bt_bb_common.c:1154.
     */
}

/* LE_fill_tx_buffer_1010 bt_bb_common.c:1186 @ bt_bb_common.o size 237B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51004, 0x3ff51010, 0x3ff5101c, 0x60012000, 0x60012004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_fill_tx_buffer_1010(void)
{
    /* DWARF locals: u32 i@l1187 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <LE_fill_tx_buffer_1010> (87 insns) + DWARF line rows for bt_bb_common.c:1186.
     */
}

/* LE_fill_tx_header_adv bt_bb_common.c:1170 @ bt_bb_common.o size 73B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60012004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_fill_tx_header_adv(u32 type, u32 length)
{
    (void)type;
    (void)length;
    /* DWARF locals: u32 header@l1171 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <LE_fill_tx_header_adv> (26 insns) + DWARF line rows for bt_bb_common.c:1170.
     */
}

/* LE_fill_tx_header_data bt_bb_common.c:1176 @ bt_bb_common.o size 67B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60012004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_fill_tx_header_data(u32 length)
{
    (void)length;
    /* DWARF locals: u32 header@l1177 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <LE_fill_tx_header_data> (24 insns) + DWARF line rows for bt_bb_common.c:1176.
     */
}

/* LE_fill_tx_payload_byte bt_bb_common.c:1182 @ bt_bb_common.o size 63B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_fill_tx_payload_byte(u32 nbyte, u32 data)
{
    (void)nbyte;
    (void)data;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <LE_fill_tx_payload_byte> (23 insns) + DWARF line rows for bt_bb_common.c:1182.
     */
}

/* LE_start_tx bt_bb_common.c:1201 @ bt_bb_common.o size 378B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, BT_tx_8m_enable, .text.BT_tx_LE_en$part$4+0xc, LE_fill_tx_buffer_1010, GetStopCmd, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, BT_tx_8m_enable, GetStopCmd, LE_fill_tx_buffer_1010, ets_delay_us, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff51000, 0x3ff51004, 0x3ff51008, 0x3ff5100c, 0x3ff51030, 0x3ff51038, 0x3ff5103c, 0x3ff51044, 0x3ff5c080
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_start_tx(u32 channel, u32 data_type, u32 loop)
{
    (void)channel;
    (void)data_type;
    (void)loop;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <LE_start_tx> (139 insns) + DWARF line rows for bt_bb_common.c:1201.
     * Ordered callee relocs: set_chan_freq_sw_start, BT_tx_8m_enable, .text.BT_tx_LE_en$part$4+0xc, LE_fill_tx_buffer_1010, GetStopCmd, ets_delay_us, phy_printf.
     */
}

/* bt_bb_rx_start_int_init bt_bb_common.c:1106 @ bt_bb_common.o size 39B [dwarf-sig]
 * Calls: phy_bt_pll_track, phy_bt_power_track | Data refs: phy_bt_pll_track, phy_bt_power_track | MMIO: 0x3ff5102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_rx_start_int_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <bt_bb_rx_start_int_init> (15 insns) + DWARF line rows for bt_bb_common.c:1106.
     * Ordered callee relocs: phy_bt_pll_track, phy_bt_power_track.
     */
}

/* bt_bb_rx_start_service bt_bb_common.c:1113 @ bt_bb_common.o size 40B [dwarf-sig]
 * Calls: bt_track_pll_cap | Data refs: bt_track_pll_cap | MMIO: 0x3ff51034, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_rx_start_service(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <bt_bb_rx_start_service> (15 insns) + DWARF line rows for bt_bb_common.c:1113.
     * Ordered callee relocs: bt_track_pll_cap.
     */
}

/* bt_bb_tx_end_int_init bt_bb_common.c:1090 @ bt_bb_common.o size 39B [dwarf-sig]
 * Calls: phy_bt_pll_track, phy_bt_power_track | Data refs: phy_bt_pll_track, phy_bt_power_track | MMIO: 0x3ff5102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_tx_end_int_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <bt_bb_tx_end_int_init> (15 insns) + DWARF line rows for bt_bb_common.c:1090.
     * Ordered callee relocs: phy_bt_pll_track, phy_bt_power_track.
     */
}

/* bt_bb_tx_end_service bt_bb_common.c:1097 @ bt_bb_common.o size 40B [dwarf-sig]
 * Calls: bt_track_pll_cap | Data refs: bt_track_pll_cap | MMIO: 0x3ff51034, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_tx_end_service(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <bt_bb_tx_end_service> (15 insns) + DWARF line rows for bt_bb_common.c:1097.
     * Ordered callee relocs: bt_track_pll_cap.
     */
}

/* bt_rw_start_int_init bt_bb_common.c:1123 @ bt_bb_common.o size 39B [dwarf-sig]
 * Calls: phy_bt_pll_track, phy_bt_power_track | Data refs: phy_bt_pll_track, phy_bt_power_track | MMIO: 0x3ff510f8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_rw_start_int_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <bt_rw_start_int_init> (15 insns) + DWARF line rows for bt_bb_common.c:1123.
     * Ordered callee relocs: phy_bt_pll_track, phy_bt_power_track.
     */
}

/* bt_rw_start_service bt_bb_common.c:1130 @ bt_bb_common.o size 40B [dwarf-sig]
 * Calls: bt_track_pll_cap | Data refs: bt_track_pll_cap | MMIO: 0x3ff51100, 0x3ff51104
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_rw_start_service(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <bt_rw_start_service> (15 insns) + DWARF line rows for bt_bb_common.c:1130.
     * Ordered callee relocs: bt_track_pll_cap.
     */
}

/* hoppe_tx_tone bt_bb_common.c:467 @ bt_bb_common.o size 150B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff46090, 0x60002000, 0x60002004, 0x60002010, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int hoppe_tx_tone(uint16 freq, uint16 delay_num, S16 reg_freq_1, U8 tone1_atten, int bt, int * alltime)
{
    (void)freq;
    (void)delay_num;
    (void)reg_freq_1;
    (void)tone1_atten;
    (void)bt;
    (void)alltime;
    /* DWARF locals: sint16[] freq_offset_tab@l469, int i@l470, uint32 * chan_param@l472, uint32 * param_flag@l474, uint32_t stime@l477, uint32_t etime@l479 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_bb_common.rdis
     * function <hoppe_tx_tone> (56 insns) + DWARF line rows for bt_bb_common.c:467.
     */
}

/* Undefined refs (10): BT_init_rx_filters, BT_tx_8m_enable, GetStopCmd, bt_track_pll_cap, ets_delay_us, memcpy, phy_bt_pll_track, phy_bt_power_track, phy_printf, set_chan_freq_sw_start */