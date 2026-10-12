/* Reconstruction of mac_common.o (librftest.a)
 * CU: mac_common.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 36 | funcdb functions: 22
 * Disasm: re/esp32-phy/disasm/librftest/mac_common.rdis
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

/* BackOffCountGet mac_common.c:289 @ mac_common.o size 143B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: .rodata.BackOffCountGet, esp_dport_access_reg_read | MMIO: 0x60033ce4, 0x60033cec, 0x60033cf4, 0x60033cfc, 0x60033d04, 0x60033d0c, 0x60033d14, 0x60033d1c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 BackOffCountGet(unsigned int queue)
{
    (void)queue;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <BackOffCountGet> (48 insns) + DWARF line rows for mac_common.c:289.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* ConfAddrGet mac_common.c:272 @ mac_common.o size 22B [dwarf-sig-decl]
 * Calls: (none) | Data refs: .rodata.CSWTCH$51 | MMIO: 0x60033d1c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 ConfAddrGet(unsigned int queue)
{
    (void)queue;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <ConfAddrGet> (8 insns) + DWARF line rows for mac_common.c:272.
     */
}

/* DurAddrGet mac_common.c:147 @ mac_common.o size 22B [dwarf-sig]
 * Calls: (none) | Data refs: .rodata.CSWTCH$41 | MMIO: 0x60034268
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 DurAddrGet(unsigned int queue)
{
    (void)queue;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <DurAddrGet> (8 insns) + DWARF line rows for mac_common.c:147.
     */
}

/* HTsigAddrGet mac_common.c:244 @ mac_common.o size 23B [dwarf-sig-decl]
 * Calls: (none) | Data refs: .rodata.CSWTCH$49 | MMIO: 0x60034260
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 HTsigAddrGet(unsigned int queue)
{
    (void)queue;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <HTsigAddrGet> (9 insns) + DWARF line rows for mac_common.c:244.
     */
}

/* Plcp0AddrGet mac_common.c:189 @ mac_common.o size 23B [dwarf-sig-decl]
 * Calls: (none) | Data refs: .rodata.CSWTCH$45 | MMIO: 0x60033d20
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 Plcp0AddrGet(unsigned int queue)
{
    (void)queue;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <Plcp0AddrGet> (9 insns) + DWARF line rows for mac_common.c:189.
     */
}

/* Plcp1AddrGet mac_common.c:217 @ mac_common.o size 23B [dwarf-sig-decl]
 * Calls: (none) | Data refs: .rodata.CSWTCH$47 | MMIO: 0x60034258
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 Plcp1AddrGet(unsigned int queue)
{
    (void)queue;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <Plcp1AddrGet> (9 insns) + DWARF line rows for mac_common.c:217.
     */
}

/* RealQGet mac_common.c:163 @ mac_common.o size 22B [dwarf-sig]
 * Calls: (none) | Data refs: .rodata.CSWTCH$43 | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 RealQGet(unsigned int queue)
{
    (void)queue;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <RealQGet> (9 insns) + DWARF line rows for mac_common.c:163.
     */
}

/* adctrig mac_common.c:652 @ mac_common.o size 506B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_delay_us, phy_printf | MMIO: 0x3ff5c02c, 0x3ffe8000, 0x60033d90, 0x60033d94
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void adctrig(int32 smp_num_aft_trig, int32 trigmode, int32 trigcase, int32 sample_88m, int32 dump_trig, int32 rx_gain_mode, int32 rx_gain, int32 rx_gain0, int32 rx_gain0_wait_us)
{
    (void)smp_num_aft_trig;
    (void)trigmode;
    (void)trigcase;
    (void)sample_88m;
    (void)dump_trig;
    (void)rx_gain_mode;
    (void)rx_gain;
    (void)rx_gain0;
    (void)rx_gain0_wait_us;
    /* DWARF locals: int32 curr_ptr@l654, int32 wrap_flag@l655 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <adctrig> (190 insns) + DWARF line rows for mac_common.c:652.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us, phy_printf.
     */
}

/* fill_tx_frame mac_common.c:366 @ mac_common.o size 1138B [dwarf-sig]
 * Calls: crypto_disable, esp_dport_access_reg_read | Data refs: .rodata.CSWTCH$45, .rodata.CSWTCH$47, .rodata.CSWTCH$49, .rodata.CSWTCH$51, PSDU0_OFFSET, PSDU1_OFFSET, PSDU2_OFFSET, PSDU3_OFFSET, TXBUF_START, crypto_disable, esp_dport_access_reg_read | MMIO: 0x60033c6c, 0x60033d1c, 0x60033d20, 0x60034258, 0x60034260
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fill_tx_frame(unsigned int tx_queue, unsigned int tx_rate, unsigned int length, unsigned int psdu0_len, unsigned int psdu1_len, unsigned int psdu2_len, unsigned int psdu3_len, uint32 key_entry_no, uint32 bssid_no, uint32 link_start_addr, uint32 gi_bit, uint32 ap_mac_5, uint32 ap_mac_4, uint32 ap_mac_3, uint32 ap_mac_2, uint32 ap_mac_1, uint32 ap_mac_0)
{
    (void)tx_queue;
    (void)tx_rate;
    (void)length;
    (void)psdu0_len;
    (void)psdu1_len;
    (void)psdu2_len;
    (void)psdu3_len;
    (void)key_entry_no;
    (void)bssid_no;
    (void)link_start_addr;
    (void)gi_bit;
    (void)ap_mac_5;
    (void)ap_mac_4;
    (void)ap_mac_3;
    (void)ap_mac_2;
    (void)ap_mac_1;
    (void)ap_mac_0;
    /* DWARF locals: unsigned int i@l368, unsigned int j@l368, unsigned char * packet0@l369, unsigned char * packet1@l370, unsigned char * packet2@l371, unsigned char * packet3@l372, unsigned int plcp0_addr@l375, unsigned int plcp1_addr@l375, unsigned int htsig_addr@l375, unsigned int legacy_len@l375, unsigned int conf_addr@l375, unsigned int queue@l376, unsigned int amp_on_ams_valid@l377, unsigned int packet_num@l379 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <fill_tx_frame> (458 insns) + DWARF line rows for mac_common.c:366.
     * Ordered callee relocs: crypto_disable, esp_dport_access_reg_read.
     */
}

/* mac_buffer_get mac_common.c:40 @ mac_common.o size 173B [dwarf-sig-decl]
 * Calls: (none) | Data refs: PSDU0_OFFSET, PSDU1_OFFSET, PSDU2_OFFSET, PSDU3_OFFSET, RX_ampdu_buff0_buf, RX_ampdu_buff0_start, RX_ampdu_entry0_buf, RX_ampdu_entry0_start, RX_ampdu_entrysd0_buf, RX_ampdu_entrysd0_start, RX_aplenbk, RX_aplenbk_start, RX_aplkbk, RX_aplkbk_start, RX_bufflk, RX_bufflk_start, TXBUF_START, txbuffer | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void mac_buffer_get(void)
{
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <mac_buffer_get> (75 insns) + DWARF line rows for mac_common.c:40.
     */
}

/* mac_init mac_common.c:66 @ mac_common.o size 701B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, rx_ampdu_buffer_fresh, rx_ampdu_entry_fresh, rx_ampdu_entrysd_fresh | Data refs: PSDU0_OFFSET, PSDU1_OFFSET, PSDU2_OFFSET, PSDU3_OFFSET, RX_ampdu_buff0_buf, RX_ampdu_buff0_start, RX_ampdu_entry0_buf, RX_ampdu_entry0_start, RX_ampdu_entrysd0_buf, RX_ampdu_entrysd0_start, RX_aplenbk, RX_aplenbk_start, RX_aplkbk, RX_aplkbk_start, RX_bufflk, RX_bufflk_start, TXBUF_START, esp_dport_access_reg_read, rx_ampdu_buffer_fresh, rx_ampdu_entry_fresh, rx_ampdu_entrysd_fresh, txbuffer | MMIO: 0x3ff000a8, 0x60033040, 0x60033044, 0x60033080, 0x60033084, 0x60033088, 0x600330d8, 0x600330dc, 0x600330e0, 0x600330e4, 0x60033c24, 0x60033c40, 0x60033c6c, 0x60033d1c, 0x60033d24, 0x60033dc4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void mac_init(void)
{
    /* DWARF locals: const unsigned int mac_upper@l75, const unsigned int mac_lower@l76 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <mac_init> (272 insns) + DWARF line rows for mac_common.c:66.
     * Ordered callee relocs: esp_dport_access_reg_read, rx_ampdu_buffer_fresh, rx_ampdu_entry_fresh, rx_ampdu_entrysd_fresh.
     */
}

/* mac_read mac_common.c:32 @ mac_common.o size 10B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
unsigned int mac_read(unsigned int addr)
{
    (void)addr;
    /* DWARF locals: unsigned int value@l34 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <mac_read> (4 insns) + DWARF line rows for mac_common.c:32.
     */
}

/* mac_write mac_common.c:27 @ mac_common.o size 10B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void mac_write(unsigned int addr, unsigned int value)
{
    (void)addr;
    (void)value;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <mac_write> (4 insns) + DWARF line rows for mac_common.c:27.
     */
}

/* rx_ampdu_buffer_fresh mac_common.c:588 @ mac_common.o size 113B [dwarf-sig]
 * Calls: (none) | Data refs: RX_bufflk_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_ampdu_buffer_fresh(unsigned int rx_ampdu_buff_start, unsigned int rx_ampdu_buff_size)
{
    (void)rx_ampdu_buff_start;
    (void)rx_ampdu_buff_size;
    /* DWARF locals: uint32_t rxbuf_num@l590, uint32_t i@l591, uint32_t last_rx_bufflk@l592 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_ampdu_buffer_fresh> (47 insns) + DWARF line rows for mac_common.c:588.
     */
}

/* rx_ampdu_buffer_init mac_common.c:581 @ mac_common.o size 28B [dwarf-sig-decl]
 * Calls: rx_ampdu_buffer_fresh | Data refs: RX_bufflk_start, rx_ampdu_buffer_fresh | MMIO: 0x60033088
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_ampdu_buffer_init(unsigned int rx_ampdu_buff_start, unsigned int rx_ampdu_buff_size)
{
    (void)rx_ampdu_buff_start;
    (void)rx_ampdu_buff_size;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_ampdu_buffer_init> (11 insns) + DWARF line rows for mac_common.c:581.
     * Ordered callee relocs: rx_ampdu_buffer_fresh.
     */
}

/* rx_ampdu_entry_fresh mac_common.c:612 @ mac_common.o size 112B [dwarf-sig]
 * Calls: (none) | Data refs: RX_aplkbk_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_ampdu_entry_fresh(unsigned int rx_ampdu_entry_start, unsigned int rx_ampdu_entry_size)
{
    (void)rx_ampdu_entry_start;
    (void)rx_ampdu_entry_size;
    /* DWARF locals: uint32_t rxbuf_num@l614, uint32_t i@l615, uint32_t last_rx_bufflk@l616 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_ampdu_entry_fresh> (47 insns) + DWARF line rows for mac_common.c:612.
     */
}

/* rx_ampdu_entry_init mac_common.c:603 @ mac_common.o size 15B [dwarf-sig-decl]
 * Calls: rx_ampdu_entry_fresh | Data refs: rx_ampdu_entry_fresh | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_ampdu_entry_init(unsigned int rx_ampdu_entry_start, unsigned int rx_ampdu_entry_size)
{
    (void)rx_ampdu_entry_start;
    (void)rx_ampdu_entry_size;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_ampdu_entry_init> (6 insns) + DWARF line rows for mac_common.c:603.
     * Ordered callee relocs: rx_ampdu_entry_fresh.
     */
}

/* rx_ampdu_entrysd_fresh mac_common.c:636 @ mac_common.o size 112B [dwarf-sig]
 * Calls: (none) | Data refs: RX_aplenbk_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_ampdu_entrysd_fresh(unsigned int rx_ampdu_entrysd_start, unsigned int rx_ampdu_entrysd_size)
{
    (void)rx_ampdu_entrysd_start;
    (void)rx_ampdu_entrysd_size;
    /* DWARF locals: uint32_t rxbuf_num@l638, uint32_t i@l639, uint32_t last_rx_bufflk@l640 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_ampdu_entrysd_fresh> (47 insns) + DWARF line rows for mac_common.c:636.
     */
}

/* rx_ampdu_entrysd_init mac_common.c:627 @ mac_common.o size 15B [dwarf-sig-decl]
 * Calls: rx_ampdu_entrysd_fresh | Data refs: rx_ampdu_entrysd_fresh | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_ampdu_entrysd_init(unsigned int rx_ampdu_entrysd_start, unsigned int rx_ampdu_entrysd_size)
{
    (void)rx_ampdu_entrysd_start;
    (void)rx_ampdu_entrysd_size;
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_ampdu_entrysd_init> (6 insns) + DWARF line rows for mac_common.c:627.
     * Ordered callee relocs: rx_ampdu_entrysd_fresh.
     */
}

/* rx_buffer_ena mac_common.c:576 @ mac_common.o size 27B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x60033084
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_buffer_ena(void)
{
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_buffer_ena> (10 insns) + DWARF line rows for mac_common.c:576.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rx_buffer_init mac_common.c:532 @ mac_common.o size 150B [dwarf-sig]
 * Calls: (none) | Data refs: RX_bufflk_start | MMIO: 0x60033084, 0x60033088
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_buffer_init(unsigned int rx_buff_start, unsigned int rx_buff_size)
{
    (void)rx_buff_start;
    (void)rx_buff_size;
    /* DWARF locals: uint32_t rxbuf_num@l541, uint32_t i@l542, uint32_t last_rx_bufflk@l543 */
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_buffer_init> (63 insns) + DWARF line rows for mac_common.c:532.
     */
}

/* rx_link_des mac_common.c:569 @ mac_common.o size 34B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x60033084
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_link_des(void)
{
    /* TODO(ground-truth): reconstruct from librftest/mac_common.rdis
     * function <rx_link_des> (13 insns) + DWARF line rows for mac_common.c:569.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* Undefined refs (4): crypto_disable, esp_dport_access_reg_read, ets_delay_us, phy_printf */