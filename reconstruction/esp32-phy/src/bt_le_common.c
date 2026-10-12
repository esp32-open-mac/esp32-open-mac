/* Reconstruction of bt_le_common.o (libbttestmode.a)
 * CU: bt_le_common.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 62 | funcdb functions: 36
 * Disasm: re/esp32-phy/disasm/libbttestmode/bt_le_common.rdis
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

/* LE_rx_ber bt_le_common.c:443 @ bt_le_common.o size 567B [dwarf-sig]
 * Calls: le_init_loopback, prbs9_gen, GetStopCmd, LE_rx_prbs9_status, phy_printf | Data refs: .rodata.str1.4, GetStopCmd, LE_rx_prbs9_status, PRBS9, g_phyFuns, le_init_loopback, phy_printf, prbs9_gen | MMIO: 0x3ff51074, 0x3ff51078, 0x3fffffff, 0x40000000, 0x60032408, 0x6003240c, 0x60032418, 0x60032424, 0x6003242c, 0x60032434, 0x6003243c, 0x60032454, 0x60032458
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_rx_ber(u32 bits, u32 type, u32 chan_id)
{
    (void)bits;
    (void)type;
    (void)chan_id;
    /* DWARF locals: u32 cmd@l444, u32 exit@l444, u32 i@l444, u32 value@l444, u32 noise@l444, u32 total_bits@l464, u32 err_bits@l464, u32 rx_status@l464, u32 get_total_bits@l464, u32 get_err_bits@l464, u32 sum_pwr@l464, u32 np@l464, u32 ncp@l464, u32 ncrc@l464, u32 necp@l464 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <LE_rx_ber> (222 insns) + DWARF line rows for bt_le_common.c:443.
     * Ordered callee relocs: le_init_loopback, prbs9_gen, GetStopCmd, LE_rx_prbs9_status, phy_printf.
     */
}

/* LE_rx_per bt_le_common.c:336 @ bt_le_common.o size 912B [dwarf-sig]
 * Calls: le_init_loopback, BT_get_pwr, phy_printf, GetStopCmd | Data refs: .rodata.LE_rx_per, .rodata.str1.4, BT_get_pwr, GetStopCmd, g_phyFuns, le_init_loopback, phy_printf | MMIO: 0x3ff51050, 0x3ff5106c, 0x3ff51074, 0x3ff51078, 0x3ff5c0d0, 0x3fffffff, 0x40000000, 0x60032408, 0x6003240c, 0x60032418, 0x60032424, 0x6003242c, 0x60032430, 0x60032434, 0x6003243c, 0x60032454, 0x60032458
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_rx_per(u32 chan_id, u32 type)
{
    (void)chan_id;
    (void)type;
    /* DWARF locals: u32 cmd@l337, u32 exit@l337, u32 i@l337, u32 value@l337, u32 noise@l337, u32 noise_min_1m@l337, u32 noise_average_1m@l337, u32 noise_filted_1m@l337, u32 total_p@l362, u32 psk_sync_ep@l362, u32 rx_status@l362, u32 cp@l362, u32 crc_ep@l362, u32 agc_reset_ep@l362, u32 fifo_ovfl_ep@l362, u32 crypt_ep@l362 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <LE_rx_per> (337 insns) + DWARF line rows for bt_le_common.c:336.
     * Ordered callee relocs: le_init_loopback, BT_get_pwr, phy_printf, GetStopCmd.
     */
}

/* LE_rx_per_debug bt_le_common.c:435 @ bt_le_common.o size 16B [dwarf-sig]
 * Calls: LE_rx_per | Data refs: LE_rx_per | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_rx_per_debug(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <LE_rx_per_debug> (6 insns) + DWARF line rows for bt_le_common.c:435.
     * Ordered callee relocs: LE_rx_per.
     */
}

/* LE_rx_prbs9_status bt_le_common.c:288 @ bt_le_common.o size 145B [dwarf-sig]
 * Calls: (none) | Data refs: PRBS9 | MMIO: 0x60032444
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void LE_rx_prbs9_status(u32 * total_bits, u32 * err_bits, u32 type)
{
    (void)total_bits;
    (void)err_bits;
    (void)type;
    /* DWARF locals: u32 rx_base@l289, u32 rx_length@l290, u32 word_len@l291, u32 byte_remain@l292, u32 last_mask@l293, u32 i@l309, u32 rdata@l309, u32 j@l309 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <LE_rx_prbs9_status> (54 insns) + DWARF line rows for bt_le_common.c:288.
     */
}

/* fill_ADV_PAC bt_le_common.c:265 @ bt_le_common.o size 74B [dwarf-sig]
 * Calls: set_le_tx_attributes | Data refs: set_le_tx_attributes | MMIO: 0x60032420
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fill_ADV_PAC(u32 PDU_type, u32 TxAdd, u32 RxAdd, u32 len, u32 payload_link)
{
    (void)PDU_type;
    (void)TxAdd;
    (void)RxAdd;
    (void)len;
    (void)payload_link;
    /* DWARF locals: u32 header@l266 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <fill_ADV_PAC> (27 insns) + DWARF line rows for bt_le_common.c:265.
     * Ordered callee relocs: set_le_tx_attributes.
     */
}

/* fill_DATA_PAC bt_le_common.c:272 @ bt_le_common.o size 82B [dwarf-sig]
 * Calls: set_le_tx_attributes | Data refs: set_le_tx_attributes | MMIO: 0x60032420
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fill_DATA_PAC(u32 LLID, u32 SN, u32 NESN, u32 MD, u32 len, u32 payload_link)
{
    (void)LLID;
    (void)SN;
    (void)NESN;
    (void)MD;
    (void)len;
    (void)payload_link;
    /* DWARF locals: u32 header@l273 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <fill_DATA_PAC> (30 insns) + DWARF line rows for bt_le_common.c:272.
     * Ordered callee relocs: set_le_tx_attributes.
     */
}

/* fill_TEST_PAC bt_le_common.c:1221 @ bt_le_common.o size 60B [dwarf-sig]
 * Calls: fill_ADV_PAC | Data refs: PRBS9, fill_ADV_PAC | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fill_TEST_PAC(LE_DTM_state * state)
{
    (void)state;
    /* DWARF locals: u32[] ADV_PAYLOAD@l1222, u32 i@l1223, u32 pattern@l1223, u32 word_len@l1224 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <fill_TEST_PAC> (24 insns) + DWARF line rows for bt_le_common.c:1221.
     * Ordered callee relocs: fill_ADV_PAC.
     */
}

/* get_ADV_PDU_header bt_le_common.c:256 @ bt_le_common.o size 36B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 get_ADV_PDU_header(u32 rx_base, LE_rx_adv_header * header)
{
    (void)rx_base;
    (void)header;
    /* DWARF locals: u32 data@l257 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <get_ADV_PDU_header> (14 insns) + DWARF line rows for bt_le_common.c:256.
     */
}

/* get_ADV_PDU_type bt_le_common.c:251 @ bt_le_common.o size 13B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 get_ADV_PDU_type(u32 rx_base)
{
    (void)rx_base;
    /* DWARF locals: u32 header@l252 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <get_ADV_PDU_type> (5 insns) + DWARF line rows for bt_le_common.c:251.
     */
}

/* get_le_payload_4byte bt_le_common.c:114 @ bt_le_common.o size 15B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 get_le_payload_4byte(u32 rx_base, u32 i)
{
    (void)rx_base;
    (void)i;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <get_le_payload_4byte> (6 insns) + DWARF line rows for bt_le_common.c:114.
     */
}

/* get_le_rx_header bt_le_common.c:103 @ bt_le_common.o size 13B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 get_le_rx_header(u32 rx_base)
{
    (void)rx_base;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <get_le_rx_header> (5 insns) + DWARF line rows for bt_le_common.c:103.
     */
}

/* get_le_rx_len bt_le_common.c:108 @ bt_le_common.o size 21B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 get_le_rx_len(u32 rx_base, u32 type)
{
    (void)rx_base;
    (void)type;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <get_le_rx_len> (8 insns) + DWARF line rows for bt_le_common.c:108.
     */
}

/* le_bb_init bt_le_common.c:18 @ bt_le_common.o size 14B [dwarf-sig-decl]
 * Calls: BT_tx_LE_en | Data refs: BT_tx_LE_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_bb_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_bb_init> (5 insns) + DWARF line rows for bt_le_common.c:18.
     * Ordered callee relocs: BT_tx_LE_en.
     */
}

/* le_dtm bt_le_common.c:1318 @ bt_le_common.o size 889B [dwarf-sig]
 * Calls: GetUartDevice, prbs9_gen, BT_tx_LE_en, ets_isr_attach, ets_isr_unmask, le_dtm_rsp, set_chan_freq_sw_start, fill_TEST_PAC, .text.le_dtm_tx_timer$part$2+0xc, le_dtm_tx_timer, phy_printf | Data refs: .rodata.str1.4, BT_tx_LE_en, GetUartDevice, PRBS9, cmd, core, ets_isr_attach, ets_isr_unmask, fill_TEST_PAC, le_dtm_rsp, le_dtm_tx_timer, le_uart_intr, new_cmd, phy_printf, prbs9_gen, rx_pac, set_chan_freq_sw_start | MMIO: 0x3ff4e0c4, 0x3ff51044, 0x3ff5c0d0, 0x3ffc9000, 0x3fffffff, 0x40000000, 0x60032408, 0x6003240c, 0x60032414, 0x60032418, 0x6003241c, 0x60032424, 0x60032428, 0x6003242c, 0x60032434, 0x6003243c, 0x60032444, 0x60032454, 0x60032458
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_dtm(void)
{
    /* DWARF locals: u32 status@l1319, u32 tx_status@l1319, u32 rx_status@l1319, u32 rx_end@l1319, u8 byte0@l1320, u8 byte1@l1320, UartDevice * MyUart@l1321 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_dtm> (330 insns) + DWARF line rows for bt_le_common.c:1318.
     * Ordered callee relocs: GetUartDevice, prbs9_gen, BT_tx_LE_en, ets_isr_attach, ets_isr_unmask, le_dtm_rsp, set_chan_freq_sw_start, fill_TEST_PAC, .text.le_dtm_tx_timer$part$2+0xc, le_dtm_tx_timer, phy_printf.
     */
}

/* le_dtm_rsp bt_le_common.c:1270 @ bt_le_common.o size 56B [dwarf-sig]
 * Calls: uart_tx_one_char | Data refs: rx_pac, uart_tx_one_char | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_dtm_rsp(LE_DTM_state * state)
{
    (void)state;
    /* DWARF locals: u32 event@l1271 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_dtm_rsp> (20 insns) + DWARF line rows for bt_le_common.c:1270.
     * Ordered callee relocs: uart_tx_one_char.
     */
}

/* le_dtm_state_refresh bt_le_common.c:1257 @ bt_le_common.o size 45B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_dtm_state_refresh(LE_DTM_state * state, u32 cmd)
{
    (void)state;
    (void)cmd;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_dtm_state_refresh> (19 insns) + DWARF line rows for bt_le_common.c:1257.
     */
}

/* le_dtm_tx_timer bt_le_common.c:1237 @ bt_le_common.o size 79B [dwarf-sig-decl]
 * Calls: .text.le_dtm_tx_timer$part$2+0xc | Data refs: (none) | MMIO: 0x60032434, 0x6003243c, 0x6003245c, 0x6003247c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 le_dtm_tx_timer(u32 init)
{
    (void)init;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_dtm_tx_timer> (30 insns) + DWARF line rows for bt_le_common.c:1237.
     * Ordered callee relocs: .text.le_dtm_tx_timer$part$2+0xc.
     */
}

/* le_dtm_tx_timer$part$2 bt_le_common.c:1237 @ bt_le_common.o size 70B [dwarf-sig-base-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x6003243c, 0x6003245c, 0x6003247c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 le_dtm_tx_timer$part$2(u32 init)
{
    (void)init;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_dtm_tx_timer$part$2> (27 insns) + DWARF line rows for bt_le_common.c:1237.
     */
}

/* le_init_loopback bt_le_common.c:119 @ bt_le_common.o size 62B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, BT_tx_LE_en, set_le_rx_attributes, set_le_tx_attributes | Data refs: BT_tx_LE_en, set_chan_freq_sw_start, set_le_rx_attributes, set_le_tx_attributes | MMIO: 0x3ffc9000, 0x60032444
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_init_loopback(u32 chan_id, u32 type, u32 crypt, u32 device_sel)
{
    (void)chan_id;
    (void)type;
    (void)crypt;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_init_loopback> (25 insns) + DWARF line rows for bt_le_common.c:119.
     * Ordered callee relocs: set_chan_freq_sw_start, BT_tx_LE_en, set_le_rx_attributes, set_le_tx_attributes.
     */
}

/* le_loopback_slave bt_le_common.c:177 @ bt_le_common.o size 403B [dwarf-sig]
 * Calls: set_le_tx_attributes, le_rx_compare, phy_printf | Data refs: .rodata.str1.4, le_rx_compare, phy_printf, set_le_tx_attributes | MMIO: 0x3ffc9000, 0x3ffc9004, 0x60032414, 0x6003241c, 0x60032424, 0x60032428, 0x60032434, 0x6003243c, 0x60032454
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_loopback_slave(u32 type, u32 crypt, u32 device_sel, u32 loop_time, u32 * total_bits, u32 * err_bits, u32 * ref, u32 * cnpac)
{
    (void)type;
    (void)crypt;
    (void)device_sel;
    (void)loop_time;
    (void)total_bits;
    (void)err_bits;
    (void)ref;
    (void)cnpac;
    /* DWARF locals: u32 rx_status@l178, u32 rx_len@l178, u32 last_rx_status@l178, u32 i@l179 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_loopback_slave> (156 insns) + DWARF line rows for bt_le_common.c:177.
     * Ordered callee relocs: set_le_tx_attributes, le_rx_compare, phy_printf.
     */
}

/* le_run_master bt_le_common.c:203 @ bt_le_common.o size 198B [dwarf-sig]
 * Calls: GetStopCmd | Data refs: GetStopCmd | MMIO: 0x60032414, 0x6003241c, 0x60032424, 0x60032428, 0x60032434, 0x6003243c, 0x60032454
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_run_master(u32 device_sel)
{
    (void)device_sel;
    /* DWARF locals: u32 cmd@l204 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_run_master> (73 insns) + DWARF line rows for bt_le_common.c:203.
     * Ordered callee relocs: GetStopCmd.
     */
}

/* le_rx_compare bt_le_common.c:131 @ bt_le_common.o size 113B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032110
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_rx_compare(u32 len, u32 * total_bits, u32 * err_bits, u32 * ref)
{
    (void)len;
    (void)total_bits;
    (void)err_bits;
    (void)ref;
    /* DWARF locals: u32 rx_base@l132, u32 rx_length@l133, u32 word_len@l134, u32 byte_remain@l135, u32 last_mask@l136, u32 i@l152, u32 rdata@l152, u32 j@l152 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_rx_compare> (44 insns) + DWARF line rows for bt_le_common.c:131.
     */
}

/* le_rx_en bt_le_common.c:87 @ bt_le_common.o size 53B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032424, 0x60032434, 0x6003243c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_rx_en(u32 device_sel)
{
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_rx_en> (20 insns) + DWARF line rows for bt_le_common.c:87.
     */
}

/* le_test_master bt_le_common.c:217 @ bt_le_common.o size 78B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, BT_tx_LE_en, prbs9_gen, set_le_rx_attributes, set_le_tx_attributes, le_run_master | Data refs: BT_tx_LE_en, le_run_master, prbs9_gen, set_chan_freq_sw_start, set_le_rx_attributes, set_le_tx_attributes | MMIO: 0x3ffc9000, 0x60032444
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_test_master(u32 chan_id, u32 type, u32 crypt, u32 device_sel, u32 len)
{
    (void)chan_id;
    (void)type;
    (void)crypt;
    (void)device_sel;
    (void)len;
    /* DWARF locals: u32[] my_PRBS9@l221 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_test_master> (31 insns) + DWARF line rows for bt_le_common.c:217.
     * Ordered callee relocs: set_chan_freq_sw_start, BT_tx_LE_en, prbs9_gen, set_le_rx_attributes, set_le_tx_attributes, le_run_master.
     */
}

/* le_test_slave bt_le_common.c:232 @ bt_le_common.o size 88B [dwarf-sig]
 * Calls: prbs9_gen, le_init_loopback, le_loopback_slave, phy_printf | Data refs: .rodata.str1.4, le_init_loopback, le_loopback_slave, phy_printf, prbs9_gen | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_test_slave(u32 chan_id, u32 type, u32 crypt, u32 device_sel)
{
    (void)chan_id;
    (void)type;
    (void)crypt;
    (void)device_sel;
    /* DWARF locals: u32 total_bits@l233, u32 err_bits@l233, u32 cnpac@l233, u32[] my_PRBS9@l235 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_test_slave> (35 insns) + DWARF line rows for bt_le_common.c:232.
     * Ordered callee relocs: prbs9_gen, le_init_loopback, le_loopback_slave, phy_printf.
     */
}

/* le_tx_en bt_le_common.c:71 @ bt_le_common.o size 53B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x6003241c, 0x60032434, 0x6003243c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_tx_en(u32 device_sel)
{
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_tx_en> (20 insns) + DWARF line rows for bt_le_common.c:71.
     */
}

/* le_uart_intr bt_le_common.c:1280 @ bt_le_common.o size 230B [dwarf-sig-decl]
 * Calls: (none) | Data refs: byte, cmd, idx_byte, nbyte, ncmd, new_cmd | MMIO: 0x3ff40000, 0x3ff40008, 0x3ff40010, 0x3ff4001c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void le_uart_intr(void * para)
{
    (void)para;
    /* DWARF locals: uint8 RcvChar@l1281 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_uart_intr> (92 insns) + DWARF line rows for bt_le_common.c:1280.
     */
}

/* le_wait4rx_end bt_le_common.c:94 @ bt_le_common.o size 47B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032434, 0x6003243c, 0x60032454
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 le_wait4rx_end(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_wait4rx_end> (18 insns) + DWARF line rows for bt_le_common.c:94.
     */
}

/* le_wait4tx_end bt_le_common.c:78 @ bt_le_common.o size 45B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032414, 0x60032434, 0x6003243c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 le_wait4tx_end(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <le_wait4tx_end> (17 insns) + DWARF line rows for bt_le_common.c:78.
     */
}

/* noise_init_le bt_le_common.c:282 @ bt_le_common.o size 18B [dwarf-sig-decl]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
sint16 noise_init_le(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <noise_init_le> (7 insns) + DWARF line rows for bt_le_common.c:282.
     */
}

/* set_ac_timer bt_le_common.c:59 @ bt_le_common.o size 52B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032428
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_ac_timer(u32 en, u32 delay)
{
    (void)en;
    (void)delay;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <set_ac_timer> (19 insns) + DWARF line rows for bt_le_common.c:59.
     */
}

/* set_ifs bt_le_common.c:65 @ bt_le_common.o size 80B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x6003242c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_ifs(u32 ifs, u32 rxtx_delay, u32 txrx_delay)
{
    (void)ifs;
    (void)rxtx_delay;
    (void)txrx_delay;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <set_ifs> (29 insns) + DWARF line rows for bt_le_common.c:65.
     */
}

/* set_le_rx_attributes bt_le_common.c:51 @ bt_le_common.o size 78B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x40000000, 0x60032424
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_le_rx_attributes(u32 type, u32 crypt, u32 device_sel)
{
    (void)type;
    (void)crypt;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <set_le_rx_attributes> (29 insns) + DWARF line rows for bt_le_common.c:51.
     */
}

/* set_le_rx_base bt_le_common.c:22 @ bt_le_common.o size 13B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032444
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_le_rx_base(u32 addr)
{
    (void)addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <set_le_rx_base> (5 insns) + DWARF line rows for bt_le_common.c:22.
     */
}

/* set_le_tx_attributes bt_le_common.c:27 @ bt_le_common.o size 184B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x40000000, 0x6003241c, 0x60032420
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_le_tx_attributes(u32 type, u32 crypt, u32 len, u32 link_addr, u32 device_sel)
{
    (void)type;
    (void)crypt;
    (void)len;
    (void)link_addr;
    (void)device_sel;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <set_le_tx_attributes> (66 insns) + DWARF line rows for bt_le_common.c:27.
     */
}

/* set_le_tx_header bt_le_common.c:47 @ bt_le_common.o size 30B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60032420
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_le_tx_header(u32 header)
{
    (void)header;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_le_common.rdis
     * function <set_le_tx_header> (11 insns) + DWARF line rows for bt_le_common.c:47.
     */
}

/* Undefined refs (12): BT_get_pwr, BT_tx_LE_en, GetStopCmd, GetUartDevice, PRBS9, ets_isr_attach, ets_isr_unmask, g_phyFuns, phy_printf, prbs9_gen, set_chan_freq_sw_start, uart_tx_one_char */