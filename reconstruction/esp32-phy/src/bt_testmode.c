/* Reconstruction of bt_testmode.o (libbttestmode.a)
 * CU: bt_testmode.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 240 | funcdb functions: 150
 * Disasm: re/esp32-phy/disasm/libbttestmode/bt_testmode.rdis
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

/* BT_con bt_testmode.c:2937 @ bt_testmode.o size 50B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320c8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_con(u32 device_sel)
{
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_con> (19 insns) + DWARF line rows for bt_testmode.c:2937.
     */
}

/* BT_con_loopback_df bt_testmode.c:2813 @ bt_testmode.o size 180B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ffc8000, 0x3ffc9000, 0x600320b4, 0x600320b8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_con_loopback_df(u32 device_sel)
{
    (void)device_sel;
    /* DWARF locals: u32 tx_length@l2814, u32 rx_length@l2815, u32 link_type@l2816, u32 type_code@l2817, u32 error_bits@l2818, u32 nerror_bits@l2818, int i@l2819, int rslt@l2819, int j@l2819, u32 tx_data@l2820, u32 rx_data@l2820, u32 mem_offset@l2820, u32 shift@l2820 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_con_loopback_df> (65 insns) + DWARF line rows for bt_testmode.c:2813.
     * Ordered callee relocs: phy_printf.
     */
}

/* BT_con_loopback_master bt_testmode.c:2849 @ bt_testmode.o size 243B [dwarf-sig]
 * Calls: BT_tx_sim_rx_prepare, phy_printf, BT_con_loopback_df | Data refs: .rodata.str1.4, BT_con_loopback_df, BT_tx_sim_rx_prepare, phy_printf | MMIO: 0x3ffc9000, 0x600320c0, 0x600320f4, 0x60032100, 0x60032108, 0x60032110, 0x60032120, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_con_loopback_master(u32 loopback)
{
    (void)loopback;
    /* DWARF locals: u32 fail@l2857, u32 i@l2858, u32 end_state@l2858, u32 esp@l2858 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_con_loopback_master> (89 insns) + DWARF line rows for bt_testmode.c:2849.
     * Ordered callee relocs: BT_tx_sim_rx_prepare, phy_printf, BT_con_loopback_df.
     */
}

/* BT_con_loopback_slave bt_testmode.c:2879 @ bt_testmode.o size 334B [dwarf-sig]
 * Calls: BT_rx_sim_tx_prepare, .text.BT_test_mode_fill_tx_payload_$part$4+0x18, BT_tx_sim, GetStopCmd, phy_printf | Data refs: .rodata.str1.4, BT_rx_sim_tx_prepare, BT_tx_sim, GetStopCmd, phy_printf | MMIO: 0x3ffc9000, 0x600320b0, 0x600320b4, 0x600320b8, 0x600320c0, 0x600320f4, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_con_loopback_slave(u32 link_type, u32 loopback, u32 payload_length, u32 slave_sel)
{
    (void)link_type;
    (void)loopback;
    (void)payload_length;
    (void)slave_sel;
    /* DWARF locals: u32 fail@l2891, u32 i@l2891, u32 rslt@l2891, u32 end_state@l2891, u32 esp@l2891 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_con_loopback_slave> (125 insns) + DWARF line rows for bt_testmode.c:2879.
     * Ordered callee relocs: BT_rx_sim_tx_prepare, .text.BT_test_mode_fill_tx_payload_$part$4+0x18, BT_tx_sim, GetStopCmd, phy_printf.
     */
}

/* BT_con_tx_test bt_testmode.c:1898 @ bt_testmode.o size 771B [dwarf-sig]
 * Calls: prbs9_gen, BT_mac_iqview_debug, BT_init_packet_struct, memcpy, BT_mac_tx_packet, GetStopCmd | Data refs: BT_init_packet_struct, BT_mac_iqview_debug, BT_mac_tx_packet, GetStopCmd, PRBS9, memcpy, packet_2DH1, packet_2DH3, packet_2DH5, packet_3DH1, packet_3DH3, packet_3DH5, packet_DH1, packet_DH3, packet_DH5, prbs9_gen | MMIO: 0x3ff4e0c4, 0x3ffc9000, 0x60032000, 0x60032024, 0x6003207c, 0x600320b4, 0x600320c8, 0x600320f0, 0x60032110, 0x60032134, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_con_tx_test(u32 chan_a, u32 chan_b, u32 pa_type, u32 pb_type, u32 pa_data, u32 pb_data)
{
    (void)chan_a;
    (void)chan_b;
    (void)pa_type;
    (void)pb_type;
    (void)pa_data;
    (void)pb_data;
    /* DWARF locals: u32 dataa@l1899, u32 datab@l1899, packet_struct pac_a@l1900, packet_struct pac_b@l1900 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_con_tx_test> (281 insns) + DWARF line rows for bt_testmode.c:1898.
     * Ordered callee relocs: prbs9_gen, BT_mac_iqview_debug, BT_init_packet_struct, memcpy, BT_mac_tx_packet, GetStopCmd.
     */
}

/* BT_eir_set_tx_bytelength bt_testmode.c:741 @ bt_testmode.o size 94B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320d0, 0x600320d4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_eir_set_tx_bytelength(int pheader_length, int payloadlength)
{
    (void)pheader_length;
    (void)payloadlength;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_eir_set_tx_bytelength> (34 insns) + DWARF line rows for bt_testmode.c:741.
     */
}

/* BT_eir_set_tx_type_code bt_testmode.c:751 @ bt_testmode.o size 33B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320d4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_eir_set_tx_type_code(unsigned int type_code)
{
    (void)type_code;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_eir_set_tx_type_code> (12 insns) + DWARF line rows for bt_testmode.c:751.
     */
}

/* BT_fill_eir_sample_pac bt_testmode.c:765 @ bt_testmode.o size 117B [dwarf-sig]
 * Calls: BT_eir_set_tx_bytelength | Data refs: BT_eir_set_tx_bytelength | MMIO: 0x600320cc, 0x600320d4, 0x600320e0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_fill_eir_sample_pac(u32 type, u32 pheader_len, u32 len, u32 payload_addr)
{
    (void)type;
    (void)pheader_len;
    (void)len;
    (void)payload_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_fill_eir_sample_pac> (43 insns) + DWARF line rows for bt_testmode.c:765.
     * Ordered callee relocs: BT_eir_set_tx_bytelength.
     */
}

/* BT_gen_prbs9 bt_testmode.c:2146 @ bt_testmode.o size 14B [dwarf-sig]
 * Calls: prbs9_gen | Data refs: PRBS9, prbs9_gen | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_gen_prbs9(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_gen_prbs9> (5 insns) + DWARF line rows for bt_testmode.c:2146.
     * Ordered callee relocs: prbs9_gen.
     */
}

/* BT_get_LLID bt_testmode.c:967 @ bt_testmode.o size 16B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_LLID(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_LLID> (6 insns) + DWARF line rows for bt_testmode.c:967.
     */
}

/* BT_get_fhs_clk bt_testmode.c:952 @ bt_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc901c, 0x3ffc9020
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_fhs_clk(void)
{
    /* DWARF locals: u32 clk27_2@l953 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_fhs_clk> (12 insns) + DWARF line rows for bt_testmode.c:952.
     */
}

/* BT_get_fhs_cod bt_testmode.c:962 @ bt_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9018, 0x3ffc901c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_fhs_cod(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_fhs_cod> (12 insns) + DWARF line rows for bt_testmode.c:962.
     */
}

/* BT_get_fhs_eir bt_testmode.c:958 @ bt_testmode.o size 22B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_fhs_eir(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_fhs_eir> (8 insns) + DWARF line rows for bt_testmode.c:958.
     */
}

/* BT_get_fhs_lap bt_testmode.c:934 @ bt_testmode.o size 22B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_fhs_lap(void)
{
    /* DWARF locals: u32 lap@l935 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_fhs_lap> (8 insns) + DWARF line rows for bt_testmode.c:934.
     */
}

/* BT_get_fhs_lt_addr bt_testmode.c:947 @ bt_testmode.o size 16B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc901c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_fhs_lt_addr(void)
{
    /* DWARF locals: u32 lt_addr@l948 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_fhs_lt_addr> (6 insns) + DWARF line rows for bt_testmode.c:947.
     */
}

/* BT_get_fhs_nap bt_testmode.c:943 @ bt_testmode.o size 30B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_fhs_nap(void)
{
    /* DWARF locals: u32 nap@l944 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_fhs_nap> (11 insns) + DWARF line rows for bt_testmode.c:943.
     */
}

/* BT_get_fhs_uap bt_testmode.c:939 @ bt_testmode.o size 16B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_get_fhs_uap(void)
{
    /* DWARF locals: u32 uap@l940 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_fhs_uap> (6 insns) + DWARF line rows for bt_testmode.c:939.
     */
}

/* BT_get_inq_info bt_testmode.c:2551 @ bt_testmode.o size 167B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ffc9004, 0x3ffc9014, 0x3ffc9018, 0x3ffc901c, 0x3ffc9020, 0x60032104, 0x60032108, 0x60032120
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_get_inq_info(void)
{
    /* DWARF locals: u32 intr@l2552, u32 end_state@l2553 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_get_inq_info> (61 insns) + DWARF line rows for bt_testmode.c:2551.
     * Ordered callee relocs: phy_printf.
     */
}

/* BT_init_packet_struct bt_testmode.c:280 @ bt_testmode.o size 442B [dwarf-sig]
 * Calls: (none) | Data refs: packet_2DH1, packet_2DH3, packet_2DH5, packet_2EV3, packet_2EV5, packet_3DH1, packet_3DH3, packet_3DH5, packet_3EV3, packet_3EV5, packet_AUX1, packet_DH1, packet_DH3, packet_DH5, packet_DM1, packet_DM3, packet_DM5, packet_DV, packet_EV3, packet_EV4, packet_EV5, packet_FHS, packet_HV1, packet_HV2, packet_HV3, packet_NULL, packet_POLL | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_init_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_init_packet_struct> (203 insns) + DWARF line rows for bt_testmode.c:280.
     */
}

/* BT_inq bt_testmode.c:2569 @ bt_testmode.o size 911B [dwarf-sig]
 * Calls: BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, GetStopCmd, phy_printf | Data refs: .rodata.str1.4, BT_init_rx_filters, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ff5c02c, 0x3ffc9000, 0x3ffc9004, 0x3ffc9010, 0x3ffc9014, 0x3ffc9018, 0x3ffc901c, 0x3ffc9020, 0x60032000, 0x600320c8, 0x600320cc, 0x600320d8, 0x600320dc, 0x600320f4, 0x600320fc, 0x60032104, 0x60032108, 0x60032110, 0x60032120, 0x60032130, 0x600321b8, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_inq(u32 hoppe_en)
{
    (void)hoppe_en;
    /* DWARF locals: u32 type_code@l2570, u32 cmd@l2570, u32 intr@l2570, u32 end_state@l2570, u32 nap@l2570, u32 uap@l2570, u32 lap@l2570, u32 lt_addr@l2570, u32 clk27_2@l2570, u32 clkn@l2570, u32 success@l2570, u32 rdata@l2570, u32 eir@l2570, u32 eir_state@l2570, u32 eir_firstw@l2570 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_inq> (339 insns) + DWARF line rows for bt_testmode.c:2569.
     * Ordered callee relocs: BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, GetStopCmd, phy_printf.
     */
}

/* BT_inq_scan bt_testmode.c:2658 @ bt_testmode.o size 569B [dwarf-sig]
 * Calls: BT_fill_eir_sample_pac, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, GetStopCmd, phy_printf | Data refs: .rodata.str1.4, BT_fill_eir_sample_pac, BT_init_rx_filters, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, eir_payload, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ff5c02c, 0x3ffc9000, 0x60032000, 0x600320c8, 0x600320d8, 0x600320dc, 0x600320fc, 0x60032104, 0x60032108, 0x60032110, 0x60032130, 0x600321b8, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_inq_scan(u32 hoppe_en)
{
    (void)hoppe_en;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_inq_scan> (209 insns) + DWARF line rows for bt_testmode.c:2658.
     * Ordered callee relocs: BT_fill_eir_sample_pac, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, GetStopCmd, phy_printf.
     */
}

/* BT_inquiry_scan_test bt_testmode.c:1567 @ bt_testmode.o size 853B [dwarf-sig]
 * Calls: BT_init_packet_struct, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, GetStopCmd, phy_printf, ets_delay_us | Data refs: .rodata.str1.4, BT_init_packet_struct, BT_init_rx_filters, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, ets_delay_us, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ff51030, 0x3ff51038, 0x3ff5c02c, 0x3ffc9000, 0x60032000, 0x600320b4, 0x600320c8, 0x600320d8, 0x600320dc, 0x600320fc, 0x60032104, 0x60032108, 0x60032110, 0x60032130, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_inquiry_scan_test(u32 hoppe_en, u32 chan)
{
    (void)hoppe_en;
    (void)chan;
    /* DWARF locals: u32 type_code@l1568, u32 brk@l1568, u32 timer0@l1569, u32 timer1@l1569, u32 timer_sub@l1569, u32 rdata@l1569, u32 cnt@l1570, u32 reset_cnt@l1570 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_inquiry_scan_test> (312 insns) + DWARF line rows for bt_testmode.c:1567.
     * Ordered callee relocs: BT_init_packet_struct, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, GetStopCmd, phy_printf, ets_delay_us.
     */
}

/* BT_inquiry_test bt_testmode.c:1459 @ bt_testmode.o size 845B [dwarf-sig]
 * Calls: BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, phy_printf, GetStopCmd | Data refs: .rodata.str1.4, BT_init_rx_filters, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ff51030, 0x3ff51038, 0x3ffc9000, 0x3ffc9010, 0x3ffc9014, 0x60032000, 0x600320b4, 0x600320c8, 0x600320cc, 0x600320d8, 0x600320dc, 0x600320f4, 0x600320fc, 0x60032104, 0x60032108, 0x60032110, 0x60032120, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_inquiry_test(u32 hoppe_en, u32 chan)
{
    (void)hoppe_en;
    (void)chan;
    /* DWARF locals: u32 type_code@l1460, u32 end_state@l1460, u32 rdata@l1460 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_inquiry_test> (309 insns) + DWARF line rows for bt_testmode.c:1459.
     * Ordered callee relocs: BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, phy_printf, GetStopCmd.
     */
}

/* BT_loopback_master bt_testmode.c:1239 @ bt_testmode.o size 1115B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug, BT_init_packet_struct, ets_delay_us, BT_mac_loopback_master_debug, GetStopCmd | Data refs: BT_init_packet_struct, BT_init_rx_filters, BT_mac_iqview_debug, BT_mac_loopback_master_debug, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, ets_delay_us, packet_2DH1, packet_2DH3, packet_2DH5, packet_2EV3, packet_2EV5, packet_3DH1, packet_3DH3, packet_3DH5, packet_3EV3, packet_3EV5, packet_AUX1, packet_DH1, packet_DH3, packet_DH5, packet_DM1, packet_DV, packet_EV3, packet_EV4, packet_EV5, packet_FHS, packet_HV1, packet_HV2, packet_HV3, packet_NULL, packet_POLL, set_chan_freq_sw_start | MMIO: 0x3ffc9000, 0x600320b4, 0x60032110
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_loopback_master(u32 loopback, uint16 freq_offset_500k, uint16 freq, u32 link_type, u32 nowhite)
{
    (void)loopback;
    (void)freq_offset_500k;
    (void)freq;
    (void)link_type;
    (void)nowhite;
    /* DWARF locals: int i@l1240 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_loopback_master> (415 insns) + DWARF line rows for bt_testmode.c:1239.
     * Ordered callee relocs: set_chan_freq_sw_start, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug, BT_init_packet_struct, ets_delay_us, BT_mac_loopback_master_debug, GetStopCmd.
     */
}

/* BT_loopback_slave bt_testmode.c:1399 @ bt_testmode.o size 356B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug, ets_delay_us, BT_rx_sim_debug, phy_printf, .text.BT_test_mode_fill_tx_payload_$part$4+0x18, BT_tx_sim_debug, GetStopCmd | Data refs: .rodata.str1.4, BT_init_rx_filters, BT_mac_iqview_debug, BT_rx_sim_debug, BT_tx_8m_enable, BT_tx_if_init, BT_tx_sim_debug, GetStopCmd, ets_delay_us, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ffc9000, 0x600320b0, 0x600320b4, 0x600320b8, 0x600320c0, 0x60032110
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_loopback_slave(u32 link_type, u32 loopback, u32 rx_payload_length, uint16 freq_offset_500k, uint16 freq, u32 nowhite)
{
    (void)link_type;
    (void)loopback;
    (void)rx_payload_length;
    (void)freq_offset_500k;
    (void)freq;
    (void)nowhite;
    /* DWARF locals: int i@l1400, u32 fail@l1426 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_loopback_slave> (126 insns) + DWARF line rows for bt_testmode.c:1399.
     * Ordered callee relocs: set_chan_freq_sw_start, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug, ets_delay_us, BT_rx_sim_debug, phy_printf, .text.BT_test_mode_fill_tx_payload_$part$4+0x18, BT_tx_sim_debug, GetStopCmd.
     */
}

/* BT_m_discon bt_testmode.c:2950 @ bt_testmode.o size 24B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320c8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_m_discon(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_m_discon> (9 insns) + DWARF line rows for bt_testmode.c:2950.
     */
}

/* BT_m_page bt_testmode.c:1037 @ bt_testmode.o size 766B [dwarf-sig]
 * Calls: GetStopCmd, phy_printf | Data refs: .rodata.str1.4, GetStopCmd, clk_debug1, phy_printf, tstart_debug | MMIO: 0x60032000, 0x60032024, 0x6003207c, 0x600320c4, 0x600320c8, 0x600320cc, 0x600320d8, 0x600320dc, 0x600320e0, 0x600320fc, 0x60032104, 0x60032108, 0x600321b8, 0x600321bc, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_m_page(u32 hoppe_en, u32 clk_debug, u32 lt_addr)
{
    (void)hoppe_en;
    (void)clk_debug;
    (void)lt_addr;
    /* DWARF locals: u32 cmd@l1038, u32 rdata@l1038 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_m_page> (284 insns) + DWARF line rows for bt_testmode.c:1037.
     * Ordered callee relocs: GetStopCmd, phy_printf.
     */
}

/* BT_m_set_nulap bt_testmode.c:925 @ bt_testmode.o size 110B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032090, 0x60032094, 0x60032098, 0x6003209c, 0x600320a0, 0x600320a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_m_set_nulap(u32 m_ulap, u32 m_nap, u32 s_ulap, u32 s_nap)
{
    (void)m_ulap;
    (void)m_nap;
    (void)s_ulap;
    (void)s_nap;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_m_set_nulap> (41 insns) + DWARF line rows for bt_testmode.c:925.
     */
}

/* BT_mac_loopback_df bt_testmode.c:773 @ bt_testmode.o size 182B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ffc8000, 0x3ffc9000, 0x600320b4, 0x600320b8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_mac_loopback_df(u32 device_sel)
{
    (void)device_sel;
    /* DWARF locals: u32 tx_length@l774, u32 rx_length@l775, u32 link_type@l776, u32 type_code@l777, int i@l778, int rslt@l778, u32 tx_data@l779, u32 rx_data@l779, u32 mem_offset@l779, u32 shift@l779 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_loopback_df> (66 insns) + DWARF line rows for bt_testmode.c:773.
     * Ordered callee relocs: phy_printf.
     */
}

/* BT_mac_loopback_master bt_testmode.c:824 @ bt_testmode.o size 394B [dwarf-sig]
 * Calls: BT_mac_set_tx_bytelength, BT_tx_sim, phy_printf, BT_mac_loopback_df | Data refs: .rodata.str1.4, BT_mac_loopback_df, BT_mac_set_tx_bytelength, BT_tx_sim, phy_printf | MMIO: 0x3ffc8000, 0x3ffc9000, 0x600320b4, 0x600320bc, 0x600320c0, 0x60032100, 0x60032108, 0x60032110, 0x60032120
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_loopback_master(packet_struct packet, u32 loopback)
{
    (void)packet;
    (void)loopback;
    /* DWARF locals: u32 fail@l830, u32 i@l831, u32 state@l831 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_loopback_master> (143 insns) + DWARF line rows for bt_testmode.c:824.
     * Ordered callee relocs: BT_mac_set_tx_bytelength, BT_tx_sim, phy_printf, BT_mac_loopback_df.
     */
}

/* BT_mac_loopback_master_debug bt_testmode.c:804 @ bt_testmode.o size 227B [dwarf-sig]
 * Calls: BT_mac_set_tx_bytelength, BT_tx_sim_debug, phy_printf, ets_delay_us, BT_rx_sim_debug, BT_mac_loopback_df | Data refs: .rodata.str1.4, BT_mac_loopback_df, BT_mac_set_tx_bytelength, BT_rx_sim_debug, BT_tx_sim_debug, ets_delay_us, phy_printf | MMIO: 0x3ffc8000, 0x600320b4, 0x600320bc, 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_loopback_master_debug(packet_struct packet, u32 loopback)
{
    (void)packet;
    (void)loopback;
    /* DWARF locals: u32 fail@l810 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_loopback_master_debug> (83 insns) + DWARF line rows for bt_testmode.c:804.
     * Ordered callee relocs: BT_mac_set_tx_bytelength, BT_tx_sim_debug, phy_printf, ets_delay_us, BT_rx_sim_debug, BT_mac_loopback_df.
     */
}

/* BT_mac_loopback_slave bt_testmode.c:856 @ bt_testmode.o size 353B [dwarf-sig]
 * Calls: phy_printf, .text.BT_test_mode_fill_tx_payload_$part$4+0x18, BT_tx_sim | Data refs: .rodata.str1.4, BT_tx_sim, phy_printf | MMIO: 0x3ffc9000, 0x600320b0, 0x600320b4, 0x600320b8, 0x600320c0, 0x60032100, 0x60032108, 0x60032110, 0x60032120
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_loopback_slave(u32 loopback, u32 link_type, u32 slave_sel)
{
    (void)loopback;
    (void)link_type;
    (void)slave_sel;
    /* DWARF locals: u32 fail@l857, u32 i@l857, u32 rslt@l857 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_loopback_slave> (127 insns) + DWARF line rows for bt_testmode.c:856.
     * Ordered callee relocs: phy_printf, .text.BT_test_mode_fill_tx_payload_$part$4+0x18, BT_tx_sim.
     */
}

/* BT_mac_rx_start_debug bt_testmode.c:2114 @ bt_testmode.o size 234B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug | Data refs: BT_init_rx_filters, BT_mac_iqview_debug, BT_tx_8m_enable, BT_tx_if_init, set_chan_freq_sw_start | MMIO: 0x3ff5c02c, 0x3ffc9000, 0x600320b4, 0x600320c0, 0x600320fc, 0x60032108, 0x60032110, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_rx_start_debug(u32 link_type, u32 chan)
{
    (void)link_type;
    (void)chan;
    /* DWARF locals: u32 i@l2136 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_rx_start_debug> (86 insns) + DWARF line rows for bt_testmode.c:2114.
     * Ordered callee relocs: set_chan_freq_sw_start, BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug.
     */
}

/* BT_mac_set_rx_link_type bt_testmode.c:736 @ bt_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_set_rx_link_type(unsigned int link_type, u32 device_sel)
{
    (void)link_type;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_set_rx_link_type> (12 insns) + DWARF line rows for bt_testmode.c:736.
     */
}

/* BT_mac_set_tx_bytelength bt_testmode.c:711 @ bt_testmode.o size 183B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320b0, 0x600320b8, 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_set_tx_bytelength(unsigned int tx_buf_addr, int pheader_length, int pheader1_length, int payloadlength, u32 device_sel)
{
    (void)tx_buf_addr;
    (void)pheader_length;
    (void)pheader1_length;
    (void)payloadlength;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_set_tx_bytelength> (65 insns) + DWARF line rows for bt_testmode.c:711.
     */
}

/* BT_mac_set_tx_link_type bt_testmode.c:732 @ bt_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320b4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_set_tx_link_type(unsigned int link_type, u32 device_sel)
{
    (void)link_type;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_set_tx_link_type> (12 insns) + DWARF line rows for bt_testmode.c:732.
     */
}

/* BT_mac_set_tx_type_code bt_testmode.c:728 @ bt_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_set_tx_type_code(unsigned int tx_buf_addr, unsigned int type_code, u32 device_sel)
{
    (void)tx_buf_addr;
    (void)type_code;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_set_tx_type_code> (12 insns) + DWARF line rows for bt_testmode.c:728.
     */
}

/* BT_mac_tx_packet bt_testmode.c:1838 @ bt_testmode.o size 171B [dwarf-sig]
 * Calls: BT_test_mode_fill_tx_payload, BT_mac_set_tx_bytelength, BT_tx_sim, phy_printf | Data refs: .rodata.str1.4, BT_mac_set_tx_bytelength, BT_test_mode_fill_tx_payload, BT_tx_sim, phy_printf | MMIO: 0x3ffc8000, 0x600320b4, 0x600320bc, 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_mac_tx_packet(packet_struct packet, u32 data_type)
{
    (void)packet;
    (void)data_type;
    /* DWARF locals: u32 fail@l1844 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_mac_tx_packet> (66 insns) + DWARF line rows for bt_testmode.c:1838.
     * Ordered callee relocs: BT_test_mode_fill_tx_payload, BT_mac_set_tx_bytelength, BT_tx_sim, phy_printf.
     */
}

/* BT_page bt_testmode.c:2712 @ bt_testmode.o size 379B [dwarf-sig]
 * Calls: phy_printf, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, BT_m_set_nulap, BT_m_page, GetStopCmd | Data refs: .rodata.str1.4, BT_init_rx_filters, BT_m_page, BT_m_set_nulap, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ffc9000, 0x600320b4, 0x600320e4, 0x600320f0, 0x600320f4, 0x60032110, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_page(u32 hoppe_en, u32 mulap, u32 mnap, u32 sulap, u32 snap, u32 clk_offset)
{
    (void)hoppe_en;
    (void)mulap;
    (void)mnap;
    (void)sulap;
    (void)snap;
    (void)clk_offset;
    /* DWARF locals: u32 fail@l2744, u32 i@l2744 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_page> (139 insns) + DWARF line rows for bt_testmode.c:2712.
     * Ordered callee relocs: phy_printf, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, BT_m_set_nulap, BT_m_page, GetStopCmd.
     */
}

/* BT_page_scan bt_testmode.c:2764 @ bt_testmode.o size 339B [dwarf-sig]
 * Calls: phy_printf, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, BT_s_page, GetStopCmd | Data refs: .rodata.str1.4, BT_init_rx_filters, BT_s_page, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ffc9000, 0x600320b4, 0x600320f0, 0x600320f4, 0x60032110, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_page_scan(u32 hoppe_en, u32 slave_sel)
{
    (void)hoppe_en;
    (void)slave_sel;
    /* DWARF locals: u32 fail@l2793, u32 i@l2793 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_page_scan> (124 insns) + DWARF line rows for bt_testmode.c:2764.
     * Ordered callee relocs: phy_printf, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, BT_s_page, GetStopCmd.
     */
}

/* BT_page_scan_test bt_testmode.c:1774 @ bt_testmode.o size 521B [dwarf-sig]
 * Calls: BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, phy_printf, BT_s_page, BT_mac_loopback_slave, GetStopCmd | Data refs: .rodata.str1.4, BT_init_rx_filters, BT_mac_loopback_slave, BT_s_page, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ffc9000, 0x3fff7890, 0x60032098, 0x6003209c, 0x600320a0, 0x600320a4, 0x600320b4, 0x600320c4, 0x600320c8, 0x600320f0, 0x600320f4, 0x600320fc, 0x60032110, 0x60032120, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_page_scan_test(u32 link_type, u32 hoppe_en, u32 loopback)
{
    (void)link_type;
    (void)hoppe_en;
    (void)loopback;
    /* DWARF locals: u32 fail@l1802, u32 i@l1802 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_page_scan_test> (191 insns) + DWARF line rows for bt_testmode.c:1774.
     * Ordered callee relocs: BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, phy_printf, BT_s_page, BT_mac_loopback_slave, GetStopCmd.
     */
}

/* BT_page_test bt_testmode.c:1710 @ bt_testmode.o size 557B [dwarf-sig]
 * Calls: BT_init_packet_struct, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, phy_printf, BT_m_page, BT_mac_loopback_master, GetStopCmd | Data refs: .rodata.str1.4, BT_init_packet_struct, BT_init_rx_filters, BT_m_page, BT_mac_loopback_master, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, packet_DH3, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ffc9000, 0x3fff7890, 0x60032090, 0x60032094, 0x60032098, 0x6003209c, 0x600320a0, 0x600320a4, 0x600320b4, 0x600320c4, 0x600320c8, 0x600320f0, 0x600320f4, 0x600320fc, 0x60032110, 0x60032120, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_page_test(u32 link_type, u32 hoppe_en, u32 loopback)
{
    (void)link_type;
    (void)hoppe_en;
    (void)loopback;
    /* DWARF locals: u32 fail@l1742, u32 i@l1742 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_page_test> (203 insns) + DWARF line rows for bt_testmode.c:1710.
     * Ordered callee relocs: BT_init_packet_struct, BT_tx_8m_enable, set_chan_freq_sw_start, BT_tx_if_init, BT_init_rx_filters, phy_printf, BT_m_page, BT_mac_loopback_master, GetStopCmd.
     */
}

/* BT_rx_ber bt_testmode.c:2176 @ bt_testmode.o size 1370B [dwarf-sig]
 * Calls: BT_mac_iqview_debug, prbs9_gen, ets_delay_us, BT_rx_prbs9_status, phy_printf | Data refs: .rodata.BT_rx_ber, .rodata.str1.4, BT_mac_iqview_debug, BT_rx_prbs9_status, PRBS9, ets_delay_us, g_phyFuns, phy_printf, prbs9_gen | MMIO: 0x3ff4e0c4, 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ffc9000, 0x600320b4, 0x600320c0, 0x600320fc, 0x60032100, 0x60032108, 0x60032110, 0x60032120, 0x60032134, 0x600321bc, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_ber(u32 bits, u32 link_type, u32 chan, u32 time_out, u32 be_thresh)
{
    (void)bits;
    (void)link_type;
    (void)chan;
    (void)time_out;
    (void)be_thresh;
    /* DWARF locals: u32[] gain_fcs@l2177, u32 fcs_i@l2178, u32 noise@l2180, u32 tstart@l2180, u32 tlimit@l2180, u32 pwr_in_band@l2180, u32 pwr_full_band@l2180, u32 gain@l2180, u32 value@l2180, u32 total_p@l2181, u32 hec_ep@l2181, u32 rx_status@l2181, u32 cp@l2181, u32 crc_ep@l2181, u32 type_ep@l2181, u32 len_ep@l2181 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_ber> (495 insns) + DWARF line rows for bt_testmode.c:2176.
     * Ordered callee relocs: BT_mac_iqview_debug, prbs9_gen, ets_delay_us, BT_rx_prbs9_status, phy_printf.
     */
}

/* BT_rx_content_status bt_testmode.c:1168 @ bt_testmode.o size 242B [dwarf-sig]
 * Calls: (none) | Data refs: .rodata.BT_rx_content_status, PRBS9 | MMIO: 0x60032110
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_content_status(u32 * total_bits, u32 * err_bits, u32 data_type)
{
    (void)total_bits;
    (void)err_bits;
    (void)data_type;
    /* DWARF locals: u32 rx_base@l1169, u32 rx_length@l1170, u32 word_len@l1171, u32 byte_remain@l1172, u32 last_mask@l1173, u32 i@l1189, u32 rdata@l1189, u32 j@l1189 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_content_status> (95 insns) + DWARF line rows for bt_testmode.c:1168.
     */
}

/* BT_rx_dump bt_testmode.c:2530 @ bt_testmode.o size 168B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, ets_delay_us, BT_mac_iqview_debug, adctrig | Data refs: BT_mac_iqview_debug, adctrig, ets_delay_us, set_chan_freq_sw_start | MMIO: 0x3ffc9000, 0x600320b4, 0x600320c0, 0x600320fc, 0x60032108, 0x60032110, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_dump(u32 link_type, u32 chan)
{
    (void)link_type;
    (void)chan;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_dump> (62 insns) + DWARF line rows for bt_testmode.c:2530.
     * Ordered callee relocs: set_chan_freq_sw_start, ets_delay_us, BT_mac_iqview_debug, adctrig.
     */
}

/* BT_rx_en bt_testmode.c:630 @ bt_testmode.o size 24B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_en(u32 slave_sel)
{
    (void)slave_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_en> (9 insns) + DWARF line rows for bt_testmode.c:630.
     */
}

/* BT_rx_per bt_testmode.c:2352 @ bt_testmode.o size 1255B [dwarf-sig]
 * Calls: BT_mac_iqview_debug, phy_printf, ets_delay_us, GetStopCmd | Data refs: .rodata.BT_rx_per, .rodata.str1.4, BT_mac_iqview_debug, GetStopCmd, ets_delay_us, g_phyFuns, phy_printf | MMIO: 0x3ff4e0c4, 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ffc9000, 0x600320b4, 0x600320c0, 0x600320fc, 0x60032100, 0x60032108, 0x60032110, 0x60032120, 0x60032134, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_per(u32 link_type, u32 chan)
{
    (void)link_type;
    (void)chan;
    /* DWARF locals: u32 cmd@l2353, u32 exit@l2353, u32 value@l2353, u32 noise@l2353, u32 pwr_in_band@l2353, u32 pwr_full_band@l2353, u32 gain@l2353, u32[] gain_fcs@l2354, u32 fcs_i@l2355, u32 i@l2404, u32 total_p@l2411, u32 hec_ep@l2411, u32 rx_status@l2411, u32 cp@l2411, u32 crc_ep@l2411, u32 type_ep@l2411 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_per> (456 insns) + DWARF line rows for bt_testmode.c:2352.
     * Ordered callee relocs: BT_mac_iqview_debug, phy_printf, ets_delay_us, GetStopCmd.
     */
}

/* BT_rx_prbs9_err_bits bt_testmode.c:1159 @ bt_testmode.o size 28B [dwarf-sig]
 * Calls: BT_rx_prbs9_status, phy_printf | Data refs: .rodata.str1.4, BT_rx_prbs9_status, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_prbs9_err_bits(void)
{
    /* DWARF locals: u32 err_bits@l1160, u32 total_bits@l1160 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_prbs9_err_bits> (11 insns) + DWARF line rows for bt_testmode.c:1159.
     * Ordered callee relocs: BT_rx_prbs9_status, phy_printf.
     */
}

/* BT_rx_prbs9_status bt_testmode.c:1111 @ bt_testmode.o size 119B [dwarf-sig]
 * Calls: (none) | Data refs: PRBS9 | MMIO: 0x60032110
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_rx_prbs9_status(u32 * total_bits, u32 * err_bits)
{
    (void)total_bits;
    (void)err_bits;
    /* DWARF locals: u32 rx_base@l1112, u32 rx_length@l1113, u32 word_len@l1114, u32 byte_remain@l1115, u32 last_mask@l1116, u32 i@l1132, u32 rdata@l1132, u32 j@l1132 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_prbs9_status> (46 insns) + DWARF line rows for bt_testmode.c:1111.
     */
}

/* BT_rx_sim bt_testmode.c:586 @ bt_testmode.o size 79B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9000, 0x600320c0, 0x60032100, 0x60032108, 0x60032110, 0x60032120
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_rx_sim(u32 slave_sel)
{
    (void)slave_sel;
    /* DWARF locals: u32 i@l589, u32 status@l589 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_sim> (29 insns) + DWARF line rows for bt_testmode.c:586.
     */
}

/* BT_rx_sim_debug bt_testmode.c:552 @ bt_testmode.o size 215B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff51038, 0x3ff5c02c, 0x3ffc9000, 0x600320fc, 0x60032104, 0x60032108, 0x60032120, 0x600321bc, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_rx_sim_debug(void)
{
    /* DWARF locals: u32 i@l555, u32 timer0@l556, u32 timer1@l556, u32 timer_sub@l556, u32 reset_cnt@l556 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_sim_debug> (80 insns) + DWARF line rows for bt_testmode.c:552.
     */
}

/* BT_rx_sim_tx_prepare bt_testmode.c:608 @ bt_testmode.o size 103B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9000, 0x600320b4, 0x600320c0, 0x60032104, 0x60032108, 0x60032110, 0x60032120
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_rx_sim_tx_prepare(u32 slave_sel)
{
    (void)slave_sel;
    /* DWARF locals: u32 i@l611, u32 status@l611 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_rx_sim_tx_prepare> (38 insns) + DWARF line rows for bt_testmode.c:608.
     */
}

/* BT_s_discon bt_testmode.c:2955 @ bt_testmode.o size 28B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320c8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_s_discon(u32 device_sel)
{
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_s_discon> (11 insns) + DWARF line rows for bt_testmode.c:2955.
     */
}

/* BT_s_page bt_testmode.c:984 @ bt_testmode.o size 566B [dwarf-sig]
 * Calls: GetStopCmd, phy_printf, BT_s_page_set_master_nulap | Data refs: .rodata.str1.4, BT_s_page_set_master_nulap, GetStopCmd, phy_printf, tstart_debug | MMIO: 0x60032000, 0x60032018, 0x60032024, 0x60032040, 0x60032054, 0x60032068, 0x6003207c, 0x600320c4, 0x600320c8, 0x600320d8, 0x600320dc, 0x600320fc, 0x60032104, 0x60032108, 0x600321b8, 0x600321bc, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_s_page(u32 hoppe_en, u32 clk_debug, u32 slave_sel, u32 fast)
{
    (void)hoppe_en;
    (void)clk_debug;
    (void)slave_sel;
    (void)fast;
    /* DWARF locals: u32 cmd@l985, u32 start@l985, u32 end@l985, u32 delta@l985 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_s_page> (209 insns) + DWARF line rows for bt_testmode.c:984.
     * Ordered callee relocs: GetStopCmd, phy_printf, BT_s_page_set_master_nulap.
     */
}

/* BT_s_page_set_master_nulap bt_testmode.c:973 @ bt_testmode.o size 118B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9014, 0x3ffc9018, 0x600320a0, 0x600320a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_s_page_set_master_nulap(u32 slave_sel)
{
    (void)slave_sel;
    /* DWARF locals: u32 m_lap@l974, u32 m_uap@l975, u32 m_nap@l976 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_s_page_set_master_nulap> (43 insns) + DWARF line rows for bt_testmode.c:973.
     */
}

/* BT_s_set_nulap bt_testmode.c:918 @ bt_testmode.o size 78B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032098, 0x6003209c, 0x600320a0, 0x600320a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_s_set_nulap(u32 m_ulap, u32 m_nap, u32 s_ulap, u32 s_nap)
{
    (void)m_ulap;
    (void)m_nap;
    (void)s_ulap;
    (void)s_nap;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_s_set_nulap> (29 insns) + DWARF line rows for bt_testmode.c:918.
     */
}

/* BT_set_cmd_timer bt_testmode.c:695 @ bt_testmode.o size 121B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032000, 0x60032024, 0x600320d8, 0x600320dc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_set_cmd_timer(u32 clksel, u32 time, u32 time_delay_us)
{
    (void)clksel;
    (void)time;
    (void)time_delay_us;
    /* DWARF locals: u32 clk_now@l696 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_set_cmd_timer> (44 insns) + DWARF line rows for bt_testmode.c:695.
     */
}

/* BT_set_packet_attributes bt_testmode.c:909 @ bt_testmode.o size 97B [dwarf-sig]
 * Calls: BT_mac_set_tx_bytelength | Data refs: BT_mac_set_tx_bytelength | MMIO: 0x3ffc8000, 0x600320b4, 0x600320bc, 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_set_packet_attributes(u32 type_code, u32 link_type, u32 payload_header_len, u32 payload1_header_len, u32 payload_len, u32 device_sel)
{
    (void)type_code;
    (void)link_type;
    (void)payload_header_len;
    (void)payload1_header_len;
    (void)payload_len;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_set_packet_attributes> (36 insns) + DWARF line rows for bt_testmode.c:909.
     * Ordered callee relocs: BT_mac_set_tx_bytelength.
     */
}

/* BT_test_mode_fill_tx_payload bt_testmode.c:419 @ bt_testmode.o size 103B [dwarf-sig-decl]
 * Calls: .text.BT_test_mode_fill_tx_payload_$part$4+0x18 | Data refs: .rodata.BT_test_mode_fill_tx_payload, PRBS9 | MMIO: 0x3ffc8000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_test_mode_fill_tx_payload(u32 lheader, u32 lpayload, u32 data_type, u32 loopback, u32 device_sel)
{
    (void)lheader;
    (void)lpayload;
    (void)data_type;
    (void)loopback;
    (void)device_sel;
    /* DWARF locals: u32 byte_offset@l420, u32 word_offset@l420, u32 i@l420, u32 content@l420, u32 tx_addr_base@l421, u32 rx_addr_base@l421 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_test_mode_fill_tx_payload> (38 insns) + DWARF line rows for bt_testmode.c:419.
     * Ordered callee relocs: .text.BT_test_mode_fill_tx_payload_$part$4+0x18.
     */
}

/* BT_test_mode_fill_tx_payload$part$0 bt_testmode.c:419 @ bt_testmode.o size 93B [dwarf-sig-base-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9008, 0x600320b4, 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_test_mode_fill_tx_payload$part$0(u32 lheader, u32 lpayload, u32 data_type, u32 loopback, u32 device_sel)
{
    (void)lheader;
    (void)lpayload;
    (void)data_type;
    (void)loopback;
    (void)device_sel;
    /* DWARF locals: u32 byte_offset@l420, u32 word_offset@l420, u32 i@l420, u32 content@l420, u32 tx_addr_base@l421, u32 rx_addr_base@l421 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_test_mode_fill_tx_payload$part$0> (34 insns) + DWARF line rows for bt_testmode.c:419.
     */
}

/* BT_test_mode_fill_tx_payload_ bt_testmode.c:3090 @ bt_testmode.o size 84B [dwarf-sig-decl]
 * Calls: .text.BT_test_mode_fill_tx_payload_$part$4+0x18 | Data refs: .rodata.BT_test_mode_fill_tx_payload_, PRBS9 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_test_mode_fill_tx_payload_(u32 lpayload, u32 data_type, u32 loopback, u32 device_sel, u32 tx_addr_base)
{
    (void)lpayload;
    (void)data_type;
    (void)loopback;
    (void)device_sel;
    (void)tx_addr_base;
    /* DWARF locals: u32 byte_offset@l3091, u32 word_offset@l3091, u32 i@l3091, u32 content@l3091, u32 rx_addr_base@l3092 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_test_mode_fill_tx_payload_> (31 insns) + DWARF line rows for bt_testmode.c:3090.
     * Ordered callee relocs: .text.BT_test_mode_fill_tx_payload_$part$4+0x18.
     */
}

/* BT_test_mode_fill_tx_payload_$part$4 bt_testmode.c:3090 @ bt_testmode.o size 93B [dwarf-sig-base-decl]
 * Calls: .text.BT_test_mode_fill_tx_payload_$part$4+0x18 | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_test_mode_fill_tx_payload_$part$4(u32 lpayload, u32 data_type, u32 loopback, u32 device_sel, u32 tx_addr_base)
{
    (void)lpayload;
    (void)data_type;
    (void)loopback;
    (void)device_sel;
    (void)tx_addr_base;
    /* DWARF locals: u32 byte_offset@l3091, u32 word_offset@l3091, u32 i@l3091, u32 content@l3091, u32 rx_addr_base@l3092 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_test_mode_fill_tx_payload_$part$4> (31 insns) + DWARF line rows for bt_testmode.c:3090.
     * Ordered callee relocs: .text.BT_test_mode_fill_tx_payload_$part$4+0x18.
     */
}

/* BT_test_mode_get_rx_payload_4byte bt_testmode.c:385 @ bt_testmode.o size 15B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9010
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_test_mode_get_rx_payload_4byte(u32 byte_position)
{
    (void)byte_position;
    /* DWARF locals: u32 byte@l386 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_test_mode_get_rx_payload_4byte> (6 insns) + DWARF line rows for bt_testmode.c:385.
     */
}

/* BT_test_mode_get_rx_payload_byte bt_testmode.c:378 @ bt_testmode.o size 36B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_test_mode_get_rx_payload_byte(u32 byte_position)
{
    (void)byte_position;
    /* DWARF locals: u32 word_offset@l379, u32 byte_offset@l380, u32 byte@l381 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_test_mode_get_rx_payload_byte> (13 insns) + DWARF line rows for bt_testmode.c:378.
     */
}

/* BT_test_mode_get_tx_payload_byte bt_testmode.c:390 @ bt_testmode.o size 70B [dwarf-sig-decl]
 * Calls: (none) | Data refs: .rodata.BT_test_mode_get_tx_payload_byte, PRBS9 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_test_mode_get_tx_payload_byte(u32 data_type, u32 loopback, u32 byte_offset, u32 word_offset, u32 byte_cnt, u32 rx_addr_base)
{
    (void)data_type;
    (void)loopback;
    (void)byte_offset;
    (void)word_offset;
    (void)byte_cnt;
    (void)rx_addr_base;
    /* DWARF locals: u32 content@l391 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_test_mode_get_tx_payload_byte> (26 insns) + DWARF line rows for bt_testmode.c:390.
     */
}

/* BT_testmode_fill_test_packet bt_testmode.c:3521 @ bt_testmode.o size 132B [dwarf-sig]
 * Calls: phy_printf, BT_test_mode_fill_tx_payload_ | Data refs: .rodata.str1.4, BT_test_mode_fill_tx_payload_, length_of_test_data, phy_printf, test_scenario, testmode_state, transmitter_test, tx_length | MMIO: 0x3ffc8000, 0x3ffca000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_fill_test_packet(void)
{
    /* DWARF locals: u32 tx_buffer_addr@l3522 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_fill_test_packet> (50 insns) + DWARF line rows for bt_testmode.c:3521.
     * Ordered callee relocs: phy_printf, BT_test_mode_fill_tx_payload_.
     */
}

/* BT_testmode_init bt_testmode.c:890 @ bt_testmode.o size 87B [dwarf-sig]
 * Calls: BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug | Data refs: BT_init_rx_filters, BT_mac_iqview_debug, BT_tx_8m_enable, BT_tx_if_init | MMIO: 0x3ffc9000, 0x600320b4, 0x60032110
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_init(uint16 freq_offset_500k, uint16 freq, u32 nowhite)
{
    (void)freq_offset_500k;
    (void)freq;
    (void)nowhite;
    /* DWARF locals: int i@l891 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_init> (31 insns) + DWARF line rows for bt_testmode.c:890.
     * Ordered callee relocs: BT_tx_8m_enable, BT_tx_if_init, BT_init_rx_filters, BT_mac_iqview_debug.
     */
}

/* BT_testmode_inq bt_testmode.c:3202 @ bt_testmode.o size 708B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9004, 0x3ffc9010, 0x3ffc9014, 0x3ffc9018, 0x3ffc901c, 0x3ffc9020, 0x60032000, 0x600320c8, 0x600320cc, 0x600320d8, 0x600320dc, 0x600320fc, 0x60032104, 0x60032108, 0x60032120
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_testmode_inq(u32 * nap, u32 * uap, u32 * lap, u32 * clk27_2, u32 * clkn, u32 * cod)
{
    (void)nap;
    (void)uap;
    (void)lap;
    (void)clk27_2;
    (void)clkn;
    (void)cod;
    /* DWARF locals: u32 type_code@l3203, u32 cmd@l3203, u32 intr@l3203, u32 end_state@l3203, u32 lt_addr@l3203, u32 success@l3203, u32 rdata@l3203, u32 eir@l3203, u32 eir_state@l3203, u32 eir_firstw@l3203, u32 retry@l3203 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_inq> (267 insns) + DWARF line rows for bt_testmode.c:3202.
     */
}

/* BT_testmode_inq_scan bt_testmode.c:3276 @ bt_testmode.o size 278B [dwarf-sig]
 * Calls: BT_fill_eir_sample_pac | Data refs: BT_fill_eir_sample_pac, eir_payload | MMIO: 0x60032000, 0x60032018, 0x600320c8, 0x600320d8, 0x600320dc, 0x600320e0, 0x600320fc, 0x60032104, 0x60032108
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_inq_scan(u32 fast)
{
    (void)fast;
    /* DWARF locals: u32 start@l3277, u32 end@l3277, u32 delta@l3277 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_inq_scan> (103 insns) + DWARF line rows for bt_testmode.c:3276.
     * Ordered callee relocs: BT_fill_eir_sample_pac.
     */
}

/* BT_testmode_lc_ARQN_refresh bt_testmode.c:3862 @ bt_testmode.o size 350B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, ARQN, HP_ap, HP_cp, SEQN, get_ARQN, get_SEQN, get_first_crc, get_type, ignore_payload, last_arq, last_rx_SEQN, last_tx_crc, phy_printf, retransmit, rx_status, tester_state, testmode_state | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_lc_ARQN_refresh(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_lc_ARQN_refresh> (133 insns) + DWARF line rows for bt_testmode.c:3862.
     * Ordered callee relocs: phy_printf.
     */
}

/* BT_testmode_lc_model_master bt_testmode.c:5430 @ bt_testmode.o size 668B [dwarf-sig]
 * Calls: .text.BT_wait4tx_end_$part$1+0x14, BT_wait4rx_end, LM_hopping_mode_tester, link_supervision, BT_testmode_lc_model_master_response, GetCmd_BT_testmode, phy_printf | Data refs: .rodata.str1.4, ARQN, BT_testmode_lc_model_master_response, BT_wait4rx_end, GetCmd_BT_testmode, LM_chart_almst, LM_hopping_mode_tester, LM_state, LM_xchg_state, RX_frequency, SEQN, TX_frequency, clk_debug, detach, get_first_crc, jump, last_arq, last_rx_SEQN, last_tx_old, link_supervision, nactv, next_tester_state, nidle, period_past, pheader_len, phy_printf, rpoll, rx_status, t_time, tend_debug, tester_con_to, tester_state, tpoll, tx_status, wait4tx_en_valid | MMIO: 0x40000000, 0x60032000, 0x60032018, 0x600320b0, 0x600320b4, 0x600320b8, 0x600320bc, 0x600320c0, 0x60032134, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_lc_model_master(void)
{
    /* DWARF locals: u32 cmd@l5431, u32 con@l5431, u32 con_to@l5431, u32 freqn@l5431, u32 clkn@l5431, link_supervision_struct link_supervision_core@l5432 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_lc_model_master> (255 insns) + DWARF line rows for bt_testmode.c:5430.
     * Ordered callee relocs: .text.BT_wait4tx_end_$part$1+0x14, BT_wait4rx_end, LM_hopping_mode_tester, link_supervision, BT_testmode_lc_model_master_response, GetCmd_BT_testmode, phy_printf.
     */
}

/* BT_testmode_lc_model_master_response bt_testmode.c:5388 @ bt_testmode.o size 358B [dwarf-sig]
 * Calls: phy_printf, BT_testmode_lc_ARQN_refresh, print_type4, BT_rx_content_status, BT_testmode_lm_model_tester, BT_testmode_lc_tx_model | Data refs: .rodata.str1.4, ARQN, BT_rx_content_status, BT_testmode_lc_ARQN_refresh, BT_testmode_lc_tx_model, BT_testmode_lm_model_tester, LLID, arq, check_packet, epac_type, get_ARQN, get_SEQN, get_flow, get_lt_addr, get_type, last_arq, last_tx_crc, link_type, packet_type, pheader_len, phy_printf, print_type4, retransmit, rx_status, test_scenario, tx_packet | MMIO: 0x3ffc9008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_lc_model_master_response(u32 lt_addr)
{
    (void)lt_addr;
    /* DWARF locals: u32 rx_length@l5389, u32 get_pac@l5389, u32 total_bits@l5389, u32 err_bits@l5389 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_lc_model_master_response> (132 insns) + DWARF line rows for bt_testmode.c:5388.
     * Ordered callee relocs: phy_printf, BT_testmode_lc_ARQN_refresh, print_type4, BT_rx_content_status, BT_testmode_lm_model_tester, BT_testmode_lc_tx_model.
     */
}

/* BT_testmode_lc_tx_loopback bt_testmode.c:4028 @ bt_testmode.o size 169B [dwarf-sig]
 * Calls: .text.BT_test_mode_fill_tx_payload_$part$4+0x18 | Data refs: ARQN, SEQN, wait4tx_en_valid | MMIO: 0x3ffc9000, 0x600320b0, 0x600320b4, 0x600320b8, 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_lc_tx_loopback(u32 device_sel)
{
    (void)device_sel;
    /* DWARF locals: u32 rx_length@l4029 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_lc_tx_loopback> (62 insns) + DWARF line rows for bt_testmode.c:4028.
     * Ordered callee relocs: .text.BT_test_mode_fill_tx_payload_$part$4+0x18.
     */
}

/* BT_testmode_lc_tx_model bt_testmode.c:3929 @ bt_testmode.o size 818B [dwarf-sig]
 * Calls: phy_printf, BT_mac_set_tx_bytelength | Data refs: .rodata.str1.4, ARQN, BT_mac_set_tx_bytelength, LLID_next, SEQN, TX_BUFFER_SEL, last_arq, last_arq_new, last_tx_crc, last_tx_old, packet_type_next, pheader_len_next, phy_printf, retransmit, rtx, t_time, tx_length, tx_length_next, tx_lm, tx_lm_delay, txed_lm, wait4tx_en_valid | MMIO: 0x3ffc8000, 0x600320b0, 0x600320b4, 0x600320b8, 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_lc_tx_model(u32 tx_payload, u32 device_sel, u32 lt_addr, u32 packet_type, u32 LLID, u32 packetheader_len, u32 arq)
{
    (void)tx_payload;
    (void)device_sel;
    (void)lt_addr;
    (void)packet_type;
    (void)LLID;
    (void)packetheader_len;
    (void)arq;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_lc_tx_model> (311 insns) + DWARF line rows for bt_testmode.c:3929.
     * Ordered callee relocs: phy_printf, BT_mac_set_tx_bytelength.
     */
}

/* BT_testmode_lm_model_tester bt_testmode.c:4825 @ bt_testmode.o size 2254B [dwarf-sig]
 * Calls: print_opcode_tester, phy_printf, LM_hopping_mode_tester, BT_testmode_senario_print, print_type4, LM_test_control, BT_testmode_lm_state | Data refs: .rodata.str1.4, ARQN, BT_testmode_lm_state, BT_testmode_senario_print, LLID, LMP_payload, LM_ack, LM_hopping_mode_tester, LM_state, LM_test_control, RX_frequency, TX_BUFFER_SEL, arq, check_packet, detach, epac_type, get_opcode, hopping_mode, ignore_payload, ins_count, jump, length_of_test_data, link_type, myRX_frequency, myTX_frequency, nactv, next_tester_state, nidle, packet_type, period_past, pheader_len, phy_printf, poll_period, power_control_mode, print_opcode_tester, print_type4, rpoll, rx_status, tc_linktype, tc_packet_type, test_case, test_scenario, tester_state, tpoll, tx_length, tx_packet | MMIO: 0x3ffc8000, 0x3ffc9008, 0x3ffc9010, 0x3ffca000, 0x600320b4, 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_lm_model_tester(u32 get_pac)
{
    (void)get_pac;
    /* DWARF locals: u32 tx_buffer_addr@l4826, u32 get_accepted_opcode@l4826, u32 get_ACLC@l4826, u32 get_ext_opcode@l4826 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_lm_model_tester> (908 insns) + DWARF line rows for bt_testmode.c:4825.
     * Ordered callee relocs: print_opcode_tester, phy_printf, LM_hopping_mode_tester, BT_testmode_senario_print, print_type4, LM_test_control, BT_testmode_lm_state.
     */
}

/* BT_testmode_lm_state bt_testmode.c:4464 @ bt_testmode.o size 1007B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.BT_testmode_lm_state, .rodata.str1.4, LLID, LMP_payload, LM_chart_almst, LM_state, LM_xchg_state, packet_type, pheader_len, phy_printf, tx_length, tx_packet | MMIO: 0x3ffc9010, 0x3ffc9014, 0x3ffc9018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_lm_state(u32 tx_buffer_addr, u32 get_ACLC, u32 get_opcode, u32 get_accepted_opcode, u32 get_ext_opcode)
{
    (void)tx_buffer_addr;
    (void)get_ACLC;
    (void)get_opcode;
    (void)get_accepted_opcode;
    (void)get_ext_opcode;
    /* DWARF locals: u32 rdata0@l4465, u32 rdata1@l4465, u32 TID@l4465, u32 acopcode@l4465 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_lm_state> (387 insns) + DWARF line rows for bt_testmode.c:4464.
     * Ordered callee relocs: phy_printf.
     */
}

/* BT_testmode_senario_print bt_testmode.c:4812 @ bt_testmode.o size 159B [dwarf-sig-decl]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_senario_print(u32 senario)
{
    (void)senario;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_senario_print> (53 insns) + DWARF line rows for bt_testmode.c:4812.
     * Ordered callee relocs: phy_printf.
     */
}

/* BT_testmode_tester bt_testmode.c:5631 @ bt_testmode.o size 703B [dwarf-sig]
 * Calls: prbs9_gen, phy_printf, BT_testmode_inq, BT_m_set_nulap, BT_m_page, GetCmd_BT_testmode, BT_testmode_lc_model_master | Data refs: .rodata.str1.4, BT_m_page, BT_m_set_nulap, BT_testmode_inq, BT_testmode_lc_model_master, GetCmd_BT_testmode, PRBS9, asserted_debug, detach, hopping_mode, lb_test, para_array, phy_printf, prbs9_gen, tester_con_to | MMIO: 0x3ffc9000, 0x60032098, 0x6003209c, 0x600320a0, 0x600320a4, 0x600320b4, 0x600320c4, 0x600320c8, 0x600320e4, 0x600320f4, 0x60032110, 0x60032130
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_testmode_tester(u32 ulap, u32 nap, u32 dut_lap_est)
{
    (void)ulap;
    (void)nap;
    (void)dut_lap_est;
    /* DWARF locals: u32 dut_nap@l5632, u32 dut_uap@l5632, u32 dut_lap@l5632, u32 dut_clk27_2@l5632, u32 clkn@l5632, u32 get@l5632, u32 clk_offset@l5632, u32 page_fail@l5632, u32 i@l5632, u32 cmd@l5632, u32 dut_cod@l5632, u32 cmd_state@l5632, u32 txdelay@l5632, u32 rxdelay@l5632 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_testmode_tester> (254 insns) + DWARF line rows for bt_testmode.c:5631.
     * Ordered callee relocs: prbs9_gen, phy_printf, BT_testmode_inq, BT_m_set_nulap, BT_m_page, GetCmd_BT_testmode, BT_testmode_lc_model_master.
     */
}

/* BT_tx_en bt_testmode.c:635 @ bt_testmode.o size 24B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320b4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_tx_en(u32 slave_sel)
{
    (void)slave_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_tx_en> (9 insns) + DWARF line rows for bt_testmode.c:635.
     */
}

/* BT_tx_sim bt_testmode.c:475 @ bt_testmode.o size 119B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320ac, 0x600320b4, 0x60032100, 0x60032108
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_tx_sim(u32 next_valid, u32 slave_sel)
{
    (void)next_valid;
    (void)slave_sel;
    /* DWARF locals: u32 status@l476 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_tx_sim> (44 insns) + DWARF line rows for bt_testmode.c:475.
     */
}

/* BT_tx_sim_debug bt_testmode.c:441 @ bt_testmode.o size 112B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x40000000, 0x600320ac, 0x600320b4, 0x600320fc, 0x60032104, 0x60032108, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_tx_sim_debug(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_tx_sim_debug> (42 insns) + DWARF line rows for bt_testmode.c:441.
     */
}

/* BT_tx_sim_rx_prepare bt_testmode.c:512 @ bt_testmode.o size 155B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320ac, 0x600320b4, 0x600320c0, 0x60032104, 0x60032108
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int BT_tx_sim_rx_prepare(u32 next_valid, u32 slave_sel)
{
    (void)next_valid;
    (void)slave_sel;
    /* DWARF locals: u32 status@l513 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_tx_sim_rx_prepare> (58 insns) + DWARF line rows for bt_testmode.c:512.
     */
}

/* BT_wait4rx_end bt_testmode.c:656 @ bt_testmode.o size 159B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, new_phy_db0, new_phy_db1, new_phy_db2, new_phy_db3, phy_printf | MMIO: 0x3ff000cc, 0x60032100, 0x60032104, 0x60032108, 0x60032120, 0x600321e0, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_wait4rx_end(void)
{
    /* DWARF locals: u32 status@l657 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_wait4rx_end> (61 insns) + DWARF line rows for bt_testmode.c:656.
     * Ordered callee relocs: phy_printf.
     */
}

/* BT_wait4rx_start bt_testmode.c:647 @ bt_testmode.o size 16B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_wait4rx_start(u32 slave_sel)
{
    (void)slave_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_wait4rx_start> (6 insns) + DWARF line rows for bt_testmode.c:647.
     */
}

/* BT_wait4tx_end_ bt_testmode.c:681 @ bt_testmode.o size 24B [dwarf-sig-decl]
 * Calls: .text.BT_wait4tx_end_$part$1+0x14 | Data refs: wait4tx_en_valid | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_wait4tx_end_(void)
{
    /* DWARF locals: u32 status@l682 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_wait4tx_end_> (9 insns) + DWARF line rows for bt_testmode.c:681.
     * Ordered callee relocs: .text.BT_wait4tx_end_$part$1+0x14.
     */
}

/* BT_wait4tx_end_$part$1 bt_testmode.c:681 @ bt_testmode.o size 82B [dwarf-sig-base-decl]
 * Calls: (none) | Data refs: wait4tx_en_valid | MMIO: 0x600320ac, 0x60032100, 0x60032104, 0x60032108
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 BT_wait4tx_end_$part$1(void)
{
    /* DWARF locals: u32 status@l682 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_wait4tx_end_$part$1> (31 insns) + DWARF line rows for bt_testmode.c:681.
     */
}

/* BT_wait4tx_start bt_testmode.c:642 @ bt_testmode.o size 16B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320b4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_wait4tx_start(u32 slave_sel)
{
    (void)slave_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <BT_wait4tx_start> (6 insns) + DWARF line rows for bt_testmode.c:642.
     */
}

/* GetCmd_BT_testmode bt_testmode.c:2976 @ bt_testmode.o size 219B [dwarf-sig-decl]
 * Calls: UartGetCmdLn, cmd_parse, strcmp, phy_printf | Data refs: .rodata.str1.4, UartGetCmdLn, cmd_parse, command, pString, para_array, para_num, phy_printf, strcmp | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 GetCmd_BT_testmode(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <GetCmd_BT_testmode> (79 insns) + DWARF line rows for bt_testmode.c:2976.
     * Ordered callee relocs: UartGetCmdLn, cmd_parse, strcmp, phy_printf.
     */
}

/* LM_accepted bt_testmode.c:3545 @ bt_testmode.o size 25B [dwarf-sig-decl]
 * Calls: (none) | Data refs: tx_length | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_accepted(u32 op_code, u32 tx_buffer_addr)
{
    (void)op_code;
    (void)tx_buffer_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_accepted> (10 insns) + DWARF line rows for bt_testmode.c:3545.
     */
}

/* LM_accepted_ext bt_testmode.c:3549 @ bt_testmode.o size 32B [dwarf-sig-decl]
 * Calls: (none) | Data refs: tx_length | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_accepted_ext(u32 op_code, u32 tx_buffer_addr, u32 TID)
{
    (void)op_code;
    (void)tx_buffer_addr;
    (void)TID;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_accepted_ext> (12 insns) + DWARF line rows for bt_testmode.c:3549.
     */
}

/* LM_detatch bt_testmode.c:4438 @ bt_testmode.o size 25B [dwarf-sig]
 * Calls: (none) | Data refs: tx_length | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_detatch(u32 error_code, u32 tx_buffer_addr)
{
    (void)error_code;
    (void)tx_buffer_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_detatch> (10 insns) + DWARF line rows for bt_testmode.c:4438.
     */
}

/* LM_fill_payload bt_testmode.c:3560 @ bt_testmode.o size 43B [dwarf-sig-decl]
 * Calls: (none) | Data refs: LMP_payload | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_fill_payload(u32 len, u32 tx_buffer_addr)
{
    (void)len;
    (void)tx_buffer_addr;
    /* DWARF locals: u32 i@l3561 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_fill_payload> (17 insns) + DWARF line rows for bt_testmode.c:3560.
     */
}

/* LM_get_opcode bt_testmode.c:3469 @ bt_testmode.o size 16B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9010
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 LM_get_opcode(void)
{
    /* DWARF locals: u32 opcode@l3470 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_get_opcode> (6 insns) + DWARF line rows for bt_testmode.c:3469.
     */
}

/* LM_get_test_control bt_testmode.c:3478 @ bt_testmode.o size 127B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9010, 0x3ffc9014, 0x3ffc9018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_get_test_control(u32 * test_scenario, u32 * hopping_mode, u32 * TX_frequency, u32 * RX_frequency, u32 * power_control_mode, u32 * poll_period, u32 * packet_type, u32 * length_of_test_data)
{
    (void)test_scenario;
    (void)hopping_mode;
    (void)TX_frequency;
    (void)RX_frequency;
    (void)power_control_mode;
    (void)poll_period;
    (void)packet_type;
    (void)length_of_test_data;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_get_test_control> (49 insns) + DWARF line rows for bt_testmode.c:3478.
     */
}

/* LM_hopping_mode bt_testmode.c:3490 @ bt_testmode.o size 238B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, RX_frequency, TX_frequency, hopping_mode, myRX_frequency, myTX_frequency, phy_printf, test_scenario, testmode_state, transmitter_test | MMIO: 0x60032124, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_hopping_mode(u32 freq)
{
    (void)freq;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_hopping_mode> (90 insns) + DWARF line rows for bt_testmode.c:3490.
     * Ordered callee relocs: phy_printf.
     */
}

/* LM_hopping_mode_tester bt_testmode.c:4394 @ bt_testmode.o size 286B [dwarf-sig-decl]
 * Calls: phy_printf | Data refs: .rodata.str1.4, PRBS9, RX_frequency, TX_frequency, hopping_mode, myRX_frequency, myTX_frequency, phy_printf, test_scenario, tester_state | MMIO: 0x3ffc8000, 0x3ffca000, 0x60032124, 0x600321bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_hopping_mode_tester(u32 freq)
{
    (void)freq;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_hopping_mode_tester> (110 insns) + DWARF line rows for bt_testmode.c:4394.
     * Ordered callee relocs: phy_printf.
     */
}

/* LM_not_accepted bt_testmode.c:3554 @ bt_testmode.o size 34B [dwarf-sig]
 * Calls: (none) | Data refs: tx_length | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_not_accepted(u32 op_code, u32 err_code, u32 tx_buffer_addr)
{
    (void)op_code;
    (void)err_code;
    (void)tx_buffer_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_not_accepted> (13 insns) + DWARF line rows for bt_testmode.c:3554.
     */
}

/* LM_test_activate bt_testmode.c:4426 @ bt_testmode.o size 20B [dwarf-sig-decl]
 * Calls: (none) | Data refs: tx_length | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_test_activate(u32 tx_buffer_addr)
{
    (void)tx_buffer_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_test_activate> (8 insns) + DWARF line rows for bt_testmode.c:4426.
     */
}

/* LM_test_control bt_testmode.c:4431 @ bt_testmode.o size 101B [dwarf-sig]
 * Calls: (none) | Data refs: tx_length | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LM_test_control(u32 test_scenario, u32 hopping_mode, u32 tx_freq, u32 rx_freq, u32 power_ctrl_mode, u32 poll_period, u32 packet_type, u32 len, u32 tx_buffer_addr)
{
    (void)test_scenario;
    (void)hopping_mode;
    (void)tx_freq;
    (void)rx_freq;
    (void)power_ctrl_mode;
    (void)poll_period;
    (void)packet_type;
    (void)len;
    (void)tx_buffer_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <LM_test_control> (37 insns) + DWARF line rows for bt_testmode.c:4431.
     */
}

/* RX_CONF bt_testmode.c:339 @ bt_testmode.o size 8B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320c0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 RX_CONF(u32 sel)
{
    (void)sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <RX_CONF> (3 insns) + DWARF line rows for bt_testmode.c:339.
     */
}

/* TX_CONF0 bt_testmode.c:312 @ bt_testmode.o size 8B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320b4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 TX_CONF0(u32 sel)
{
    (void)sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <TX_CONF0> (3 insns) + DWARF line rows for bt_testmode.c:312.
     */
}

/* TX_CONF1 bt_testmode.c:321 @ bt_testmode.o size 8B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320b8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 TX_CONF1(u32 sel)
{
    (void)sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <TX_CONF1> (3 insns) + DWARF line rows for bt_testmode.c:321.
     */
}

/* TX_HEAD bt_testmode.c:330 @ bt_testmode.o size 8B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 TX_HEAD(u32 sel)
{
    (void)sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <TX_HEAD> (3 insns) + DWARF line rows for bt_testmode.c:330.
     */
}

/* ac_lost_print bt_testmode.c:3326 @ bt_testmode.o size 356B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, HP_ap, HP_cp, HP_ep, HP_ep_gain0, HP_ep_gain1, HP_ep_gain2, HP_ep_gain3, HP_ep_gain_cycle, HP_gain, HP_ppt, HP_pwr_fb, HP_pwr_ib, HP_total, ac_lost, dut_boost_cnt, p_print_al, phy_printf, stage_al, t_print_al | MMIO: 0x60032000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ac_lost_print(u32 status, u32 init)
{
    (void)status;
    (void)init;
    /* DWARF locals: u32 per@l3327, u32 tp@l3327 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <ac_lost_print> (137 insns) + DWARF line rows for bt_testmode.c:3326.
     * Ordered callee relocs: phy_printf.
     */
}

/* al_get_power bt_testmode.c:3381 @ bt_testmode.o size 195B [dwarf-sig]
 * Calls: (none) | Data refs: HP_ep_gain0, HP_ep_gain1, HP_ep_gain2, HP_ep_gain3, HP_ep_gain_cycle, HP_gain, HP_pwr_fb, HP_pwr_ib, HP_total | MMIO: 0x3ff51074, 0x3ff51078
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void al_get_power(u32 rx_status)
{
    (void)rx_status;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <al_get_power> (77 insns) + DWARF line rows for bt_testmode.c:3381.
     */
}

/* bt_bblc_init bt_testmode.c:3047 @ bt_testmode.o size 41B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9000, 0x600320b4, 0x60032110
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bblc_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <bt_bblc_init> (15 insns) + DWARF line rows for bt_testmode.c:3047.
     */
}

/* freq_offset_cfg bt_testmode.c:2151 @ bt_testmode.o size 75B [dwarf-sig]
 * Calls: BT_tx_8m_enable, BT_init_rx_filters | Data refs: BT_init_rx_filters, BT_tx_8m_enable | MMIO: 0x3ff4e0c4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void freq_offset_cfg(u32 tx_offset_bb, u32 rx_offset_bb, u32 tx_offset_hoppe, u32 rx_offset_hoppe, u32 cmpx_on, u32 cmpx_offset, u32 bt_mode_force_en, u32 bt_mode_force, u32 bt_rx_force_on)
{
    (void)tx_offset_bb;
    (void)rx_offset_bb;
    (void)tx_offset_hoppe;
    (void)rx_offset_hoppe;
    (void)cmpx_on;
    (void)cmpx_offset;
    (void)bt_mode_force_en;
    (void)bt_mode_force;
    (void)bt_rx_force_on;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <freq_offset_cfg> (27 insns) + DWARF line rows for bt_testmode.c:2151.
     * Ordered callee relocs: BT_tx_8m_enable, BT_init_rx_filters.
     */
}

/* get_packetheader bt_testmode.c:3059 @ bt_testmode.o size 41B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_packetheader(u32 * LT_ADDR, u32 * TYPE, u32 * FLOW, u32 * SEQN, u32 * ARQN)
{
    (void)LT_ADDR;
    (void)TYPE;
    (void)FLOW;
    (void)SEQN;
    (void)ARQN;
    /* DWARF locals: u32 pheader@l3060 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <get_packetheader> (16 insns) + DWARF line rows for bt_testmode.c:3059.
     */
}

/* init_2DH1_packet_struct bt_testmode.c:103 @ bt_testmode.o size 28B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_2DH1 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_2DH1_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_2DH1_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:103.
     */
}

/* init_2DH3_packet_struct bt_testmode.c:248 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_2DH3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_2DH3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_2DH3_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:248.
     */
}

/* init_2DH5_packet_struct bt_testmode.c:264 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_2DH5 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_2DH5_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_2DH5_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:264.
     */
}

/* init_2EV3_packet_struct bt_testmode.c:168 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_2EV3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_2EV3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_2EV3_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:168.
     */
}

/* init_2EV5_packet_struct bt_testmode.c:184 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_2EV5 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_2EV5_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_2EV5_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:184.
     */
}

/* init_3DH1_packet_struct bt_testmode.c:240 @ bt_testmode.o size 28B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_3DH1 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_3DH1_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_3DH1_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:240.
     */
}

/* init_3DH3_packet_struct bt_testmode.c:256 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_3DH3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_3DH3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_3DH3_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:256.
     */
}

/* init_3DH5_packet_struct bt_testmode.c:272 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_3DH5 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_3DH5_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_3DH5_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:272.
     */
}

/* init_3EV3_packet_struct bt_testmode.c:176 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_3EV3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_3EV3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_3EV3_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:176.
     */
}

/* init_3EV5_packet_struct bt_testmode.c:192 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_3EV5 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_3EV5_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_3EV5_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:192.
     */
}

/* init_AUX1_packet_struct bt_testmode.c:200 @ bt_testmode.o size 28B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_AUX1 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_AUX1_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_AUX1_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:200.
     */
}

/* init_DH1_packet_struct bt_testmode.c:95 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_DH1 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_DH1_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_DH1_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:95.
     */
}

/* init_DH3_packet_struct bt_testmode.c:216 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_DH3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_DH3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_DH3_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:216.
     */
}

/* init_DH5_packet_struct bt_testmode.c:232 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_DH5 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_DH5_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_DH5_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:232.
     */
}

/* init_DM1_packet_struct bt_testmode.c:87 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_DM1 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_DM1_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_DM1_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:87.
     */
}

/* init_DM3_packet_struct bt_testmode.c:208 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_DM3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_DM3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_DM3_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:208.
     */
}

/* init_DM5_packet_struct bt_testmode.c:224 @ bt_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_DM5 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_DM5_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_DM5_packet_struct> (13 insns) + DWARF line rows for bt_testmode.c:224.
     */
}

/* init_DV_packet_struct bt_testmode.c:136 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_DV | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_DV_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_DV_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:136.
     */
}

/* init_EV3_packet_struct bt_testmode.c:144 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_EV3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_EV3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_EV3_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:144.
     */
}

/* init_EV4_packet_struct bt_testmode.c:152 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_EV4 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_EV4_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_EV4_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:152.
     */
}

/* init_EV5_packet_struct bt_testmode.c:160 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_EV5 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_EV5_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_EV5_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:160.
     */
}

/* init_FHS_packet_struct bt_testmode.c:79 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_FHS | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_FHS_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_FHS_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:79.
     */
}

/* init_HV1_packet_struct bt_testmode.c:111 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_HV1 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_HV1_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_HV1_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:111.
     */
}

/* init_HV2_packet_struct bt_testmode.c:119 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_HV2 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_HV2_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_HV2_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:119.
     */
}

/* init_HV3_packet_struct bt_testmode.c:127 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_HV3 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_HV3_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_HV3_packet_struct> (12 insns) + DWARF line rows for bt_testmode.c:127.
     */
}

/* init_NALL_packet_struct bt_testmode.c:63 @ bt_testmode.o size 22B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_NULL | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_NALL_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_NALL_packet_struct> (10 insns) + DWARF line rows for bt_testmode.c:63.
     */
}

/* init_POLL_packet_struct bt_testmode.c:71 @ bt_testmode.o size 22B [dwarf-sig-decl]
 * Calls: (none) | Data refs: packet_POLL | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void init_POLL_packet_struct(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <init_POLL_packet_struct> (10 insns) + DWARF line rows for bt_testmode.c:71.
     */
}

/* is_ACLC bt_testmode.c:3054 @ bt_testmode.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffc9008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 is_ACLC(void)
{
    /* DWARF locals: u32 LLID@l3055 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <is_ACLC> (10 insns) + DWARF line rows for bt_testmode.c:3054.
     */
}

/* link_supervision bt_testmode.c:3568 @ bt_testmode.o size 80B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void link_supervision(link_supervision_struct * param, u32 rx_status)
{
    (void)param;
    (void)rx_status;
    /* DWARF locals: u32 now@l3569, u32 delta@l3570 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <link_supervision> (35 insns) + DWARF line rows for bt_testmode.c:3568.
     */
}

/* noise_init_bt bt_testmode.c:1230 @ bt_testmode.o size 18B [dwarf-sig-decl]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
sint16 noise_init_bt(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <noise_init_bt> (7 insns) + DWARF line rows for bt_testmode.c:1230.
     */
}

/* prbs9_gen bt_testmode.c:352 @ bt_testmode.o size 82B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void prbs9_gen(u32 * pattern)
{
    (void)pattern;
    /* DWARF locals: u32 shift_reg@l353, u32 temp@l353, u32 out@l354, u32 i@l355, u32 j@l355 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <prbs9_gen> (30 insns) + DWARF line rows for bt_testmode.c:352.
     */
}

/* prbs9_test bt_testmode.c:367 @ bt_testmode.o size 31B [dwarf-sig]
 * Calls: prbs9_gen, phy_printf | Data refs: .rodata.str1.4, phy_printf, prbs9_gen | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void prbs9_test(void)
{
    /* DWARF locals: u32[] pattern@l368 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <prbs9_test> (12 insns) + DWARF line rows for bt_testmode.c:367.
     * Ordered callee relocs: prbs9_gen, phy_printf.
     */
}

/* print_opcode_DUT bt_testmode.c:3438 @ bt_testmode.o size 88B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ffc9010
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void print_opcode_DUT(u32 opcode)
{
    (void)opcode;
    /* DWARF locals: u32 acopcode@l3439 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <print_opcode_DUT> (30 insns) + DWARF line rows for bt_testmode.c:3438.
     * Ordered callee relocs: phy_printf.
     */
}

/* print_opcode_tester bt_testmode.c:4369 @ bt_testmode.o size 87B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void print_opcode_tester(u32 opcode)
{
    (void)opcode;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <print_opcode_tester> (31 insns) + DWARF line rows for bt_testmode.c:4369.
     * Ordered callee relocs: phy_printf.
     */
}

/* print_type4 bt_testmode.c:3110 @ bt_testmode.o size 434B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.print_type4, .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void print_type4(u32 type, u32 link_type)
{
    (void)type;
    (void)link_type;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <print_type4> (151 insns) + DWARF line rows for bt_testmode.c:3110.
     * Ordered callee relocs: phy_printf.
     */
}

/* set_ARQN bt_testmode.c:3073 @ bt_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_ARQN(u32 ARQN, u32 device_sel)
{
    (void)ARQN;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <set_ARQN> (12 insns) + DWARF line rows for bt_testmode.c:3073.
     */
}

/* set_LLID bt_testmode.c:3084 @ bt_testmode.o size 38B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_LLID(u32 LLID, u32 device_sel)
{
    (void)LLID;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <set_LLID> (14 insns) + DWARF line rows for bt_testmode.c:3084.
     */
}

/* set_SEQN bt_testmode.c:3078 @ bt_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_SEQN(u32 SEQN, u32 device_sel)
{
    (void)SEQN;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <set_SEQN> (12 insns) + DWARF line rows for bt_testmode.c:3078.
     */
}

/* set_eir_LLID bt_testmode.c:759 @ bt_testmode.o size 38B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320d4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_eir_LLID(u32 LLID)
{
    (void)LLID;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <set_eir_LLID> (14 insns) + DWARF line rows for bt_testmode.c:759.
     */
}

/* set_eir_packetheader bt_testmode.c:755 @ bt_testmode.o size 57B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320d4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_eir_packetheader(u32 LT_ADDR, u32 TYPE, u32 FLOW, u32 SEQN, u32 ARQN)
{
    (void)LT_ADDR;
    (void)TYPE;
    (void)FLOW;
    (void)SEQN;
    (void)ARQN;
    /* DWARF locals: u32 pheader@l756 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <set_eir_packetheader> (20 insns) + DWARF line rows for bt_testmode.c:755.
     */
}

/* set_packetheader bt_testmode.c:3068 @ bt_testmode.o size 57B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600320bc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_packetheader(u32 LT_ADDR, u32 TYPE, u32 FLOW, u32 SEQN, u32 ARQN, u32 device_sel)
{
    (void)LT_ADDR;
    (void)TYPE;
    (void)FLOW;
    (void)SEQN;
    (void)ARQN;
    (void)device_sel;
    /* DWARF locals: u32 pheader@l3069 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <set_packetheader> (20 insns) + DWARF line rows for bt_testmode.c:3068.
     */
}

/* type_check bt_testmode.c:3188 @ bt_testmode.o size 46B [dwarf-sig-decl]
 * Calls: phy_printf, print_type4 | Data refs: .rodata.str1.4, phy_printf, print_type4 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void type_check(u32 gtype, u32 link_type, u32 etype)
{
    (void)gtype;
    (void)link_type;
    (void)etype;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_testmode.rdis
     * function <type_check> (17 insns) + DWARF line rows for bt_testmode.c:3188.
     * Ordered callee relocs: phy_printf, print_type4.
     */
}

/* Undefined refs (18): BT_init_rx_filters, BT_mac_iqview_debug, BT_tx_8m_enable, BT_tx_if_init, GetStopCmd, UartGetCmdLn, adctrig, cmd_parse, command, ets_delay_us, g_phyFuns, memcpy, pString, para_array, para_num, phy_printf, set_chan_freq_sw_start, strcmp */