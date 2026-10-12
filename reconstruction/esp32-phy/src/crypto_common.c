/* Reconstruction of crypto_common.o (librftest.a)
 * CU: crypto_common.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 24 | funcdb functions: 14
 * Disasm: re/esp32-phy/disasm/librftest/crypto_common.rdis
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

/* clear_mem crypto_common.c:43 @ crypto_common.o size 22B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void clear_mem(U32 mem_start_addr, unsigned int depth)
{
    (void)mem_start_addr;
    (void)depth;
    /* DWARF locals: unsigned int i@l44 */
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <clear_mem> (9 insns) + DWARF line rows for crypto_common.c:43.
     */
}

/* clear_txdumpmem crypto_common.c:51 @ crypto_common.o size 26B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffe8000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void clear_txdumpmem(void)
{
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <clear_txdumpmem> (10 insns) + DWARF line rows for crypto_common.c:51.
     */
}

/* crypto_decap crypto_common.c:699 @ crypto_common.o size 848B [dwarf-sig]
 * Calls: mac_write, esp_dport_access_reg_read, do_decryto_poll | Data refs: do_decryto_poll, esp_dport_access_reg_read, mac_write | MMIO: 0x60033000, 0x60033004, 0x60033008, 0x6003300c, 0x60033020, 0x60033024, 0x60033028, 0x6003302c, 0x60033040, 0x60033044, 0x60033048, 0x6003304c, 0x60033060, 0x60033064, 0x60033068, 0x6003306c, 0x60033800, 0x60033804, 0x60033814
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void crypto_decap(int valid_entry_mask, int location, int addr_lo, int addr_hi, int bssid_lo, int bssid_hi, int force_keysrch, int amsdu_valid)
{
    (void)valid_entry_mask;
    (void)location;
    (void)addr_lo;
    (void)addr_hi;
    (void)bssid_lo;
    (void)bssid_hi;
    (void)force_keysrch;
    (void)amsdu_valid;
    /* DWARF locals: uint32 match_mask@l702, uint32 fc_qos_valid_bit@l703, uint32 amsdu_flag@l704, uint32 ampdu_flag@l705, uint32 multibssid_ena@l706, uint32 rx_location@l707 */
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <crypto_decap> (316 insns) + DWARF line rows for crypto_common.c:699.
     * Ordered callee relocs: mac_write, esp_dport_access_reg_read, do_decryto_poll.
     */
}

/* crypto_disable crypto_common.c:288 @ crypto_common.o size 31B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60033800, 0x60033814
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void crypto_disable(void)
{
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <crypto_disable> (13 insns) + DWARF line rows for crypto_common.c:288.
     */
}

/* crypto_encap crypto_common.c:295 @ crypto_common.o size 386B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, tx_a_frame | Data refs: esp_dport_access_reg_read, tx_a_frame | MMIO: 0x3ff00024, 0x60033000, 0x60033004, 0x60033008, 0x6003300c, 0x60033040, 0x60033044, 0x60033048, 0x6003304c, 0x60033800, 0x60033804, 0x60033814, 0x60033dc0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void crypto_encap(unsigned int que_no, uint32 location, uint32 keyentry_mask, uint32 amsdu_valid)
{
    (void)que_no;
    (void)location;
    (void)keyentry_mask;
    (void)amsdu_valid;
    /* DWARF locals: uint32 fc_qos_valid_bit@l297, uint32 amsdu_flag@l298, uint32 ampdu_flag@l299, uint32 rx_location@l300 */
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <crypto_encap> (155 insns) + DWARF line rows for crypto_common.c:295.
     * Ordered callee relocs: esp_dport_access_reg_read, tx_a_frame.
     */
}

/* crypto_enmic crypto_common.c:840 @ crypto_common.o size 298B [dwarf-sig]
 * Calls: mac_write, esp_dport_access_reg_read, mac_read, phy_printf | Data refs: .rodata.str1.4, PSDU0_OFFSET, esp_dport_access_reg_read, mac_read, mac_write, phy_printf | MMIO: 0x3ffffffe, 0x60034808, 0x6003480c, 0x60034810, 0x60034814
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void crypto_enmic(int32 data_len, int32 start_offset)
{
    (void)data_len;
    (void)start_offset;
    /* DWARF locals: int32 i@l842, int32 tmpdata@l843, int32 writetm@l844, int32 endbytenum@l845 */
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <crypto_enmic> (110 insns) + DWARF line rows for crypto_common.c:840.
     * Ordered callee relocs: mac_write, esp_dport_access_reg_read, mac_read, phy_printf.
     */
}

/* do_ampdu_rx_poll crypto_common.c:522 @ crypto_common.o size 5B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void do_ampdu_rx_poll(int32 match_mask)
{
    return;
}

/* do_decryto_poll crypto_common.c:358 @ crypto_common.o size 600B [dwarf-sig]
 * Calls: rx_buffer_ena, esp_dport_access_reg_read, phy_printf, GetStopCmd, rx_link_des | Data refs: .rodata.str1.4, GetStopCmd, esp_dport_access_reg_read, phy_printf, rx_buffer_ena, rx_link_des | MMIO: 0x3ff5c04c, 0x3ff5c050, 0x60009c44, 0x60033080, 0x60033098, 0x600330a4, 0x600330d8, 0x600330dc, 0x600330e0, 0x600330e4, 0x60033830, 0x60033c0c, 0x60033c40, 0x60033c48, 0x60033c4c, 0x60033c78
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void do_decryto_poll(int32 match_mask)
{
    (void)match_mask;
    /* DWARF locals: int gain@l360, int rssi@l361, int noise@l362, int reg_rx_gain@l363, int reg_noiseflorr@l363, int reg_rssi@l363, unsigned int state@l364, unsigned int err_stat@l364, unsigned int keyid_match@l364, int desired_count@l365, unsigned int gooddata_count@l366, unsigned int correct_count@l367, unsigned int err_count@l368, unsigned int err_fcs_count@l369, unsigned int err_fcs1_count@l370, unsigned int err_bb_count@l371 */
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <do_decryto_poll> (227 insns) + DWARF line rows for crypto_common.c:358.
     * Ordered callee relocs: rx_buffer_ena, esp_dport_access_reg_read, phy_printf, GetStopCmd, rx_link_des.
     */
}

/* get_encapaddr crypto_common.c:237 @ crypto_common.o size 5B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void get_encapaddr(void)
{
    return;
}

/* get_micaddr crypto_common.c:835 @ crypto_common.o size 22B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, PSDU0_OFFSET, phy_printf | MMIO: 0x60034800
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_micaddr(void)
{
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <get_micaddr> (8 insns) + DWARF line rows for crypto_common.c:835.
     * Ordered callee relocs: phy_printf.
     */
}

/* get_txdumpaddr crypto_common.c:279 @ crypto_common.o size 14B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffe8000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_txdumpaddr(uint32 * txdump_addr, int32 * plcp_11g_len)
{
    (void)txdump_addr;
    (void)plcp_11g_len;
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <get_txdumpaddr> (6 insns) + DWARF line rows for crypto_common.c:279.
     */
}

/* link_dscr_check crypto_common.c:59 @ crypto_common.o size 104B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int link_dscr_check(int buf_start, int buf_end, int size, int dscr_start, int dscr_end, int dscr_cnt, int last_len, int checklastlen)
{
    (void)buf_start;
    (void)buf_end;
    (void)size;
    (void)dscr_start;
    (void)dscr_end;
    (void)dscr_cnt;
    (void)last_len;
    (void)checklastlen;
    /* DWARF locals: int addr@l61, uint32_t word0@l62, uint32_t exp_word0@l62, int pass@l63 */
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <link_dscr_check> (42 insns) + DWARF line rows for crypto_common.c:59.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* oneblock_buf_init crypto_common.c:31 @ crypto_common.o size 73B [dwarf-sig]
 * Calls: mac_write, phy_printf | Data refs: .rodata.str1.4, RX_ampdu_buff0_start, mac_write, phy_printf | MMIO: 0x60033088
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void oneblock_buf_init(void)
{
    /* TODO(ground-truth): reconstruct from librftest/crypto_common.rdis
     * function <oneblock_buf_init> (26 insns) + DWARF line rows for crypto_common.c:31.
     * Ordered callee relocs: mac_write, phy_printf.
     */
}

/* rxlink_count crypto_common.c:? @ crypto_common.o size 5B [inferred]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void rxlink_count(void)
{
    return;
}

/* Undefined refs (10): GetStopCmd, PSDU0_OFFSET, RX_ampdu_buff0_start, esp_dport_access_reg_read, mac_read, mac_write, phy_printf, rx_buffer_ena, rx_link_des, tx_a_frame */