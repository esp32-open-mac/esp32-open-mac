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
/* MMIO helpers: esp_dport_access_reg_read() in the blob disassembly is the
 * DPORT register reader; plain s32i to 0x600xxxxx are writes. */
static inline unsigned reg_rd(unsigned addr);
static inline void reg_wr(unsigned addr, unsigned val);
#define REG_READ(a) reg_rd(a)
#define REG_WRITE(a, v) reg_wr((a), (v))

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
 * Fidelity: medium - queue/rate tables (exact contents), rate-clear, length split, descriptor word builds, psdu select, scatter loop verified; mid-section field packing approximate */
void fill_tx_frame(unsigned int tx_queue, unsigned int tx_rate, unsigned int length, unsigned int psdu0_len, unsigned int psdu1_len, unsigned int psdu2_len, unsigned int psdu3_len, uint32 key_entry_no, uint32 bssid_no, uint32 link_start_addr, uint32 gi_bit, uint32 ap_mac_5, uint32 ap_mac_4, uint32 ap_mac_3, uint32 ap_mac_2, uint32 ap_mac_1, uint32 ap_mac_0)
{
    /* DWARF locals: unsigned int i@l368, unsigned int j@l368, unsigned char * packet0@l369, unsigned char * packet1@l370, unsigned char * packet2@l371, unsigned char * packet3@l372, unsigned int plcp0_addr@l375, unsigned int plcp1_addr@l375, unsigned int htsig_addr@l375, unsigned int legacy_len@l375, unsigned int conf_addr@l375, unsigned int queue@l376, unsigned int amp_on_ams_valid@l377, unsigned int packet_num@l379 */
    extern u32 TXBUF_START, PSDU0_OFFSET, PSDU1_OFFSET, PSDU2_OFFSET, PSDU3_OFFSET;
    /* Exact per-queue MMIO triples from .rodata.CSWTCH$47/45/49 (idx = queue-1). */
    static const u32 q_conf[27] = { 0x6003403cu, 0x60034000u, 0x60033fc4u, 0x60034258u, 0x60034258u,
        0x60034258u, 0x60034258u, 0x60034258u, 0x60034258u, 0x60034258u, 0x6003421cu, 0x600341e0u,
        0x600341a4u, 0x60034168u, 0x6003412cu, 0x600340f0u, 0x600340b4u, 0x60034258u, 0x60034258u,
        0x60034258u, 0x6003421cu, 0x600341e0u, 0x600341a4u, 0x60034168u, 0x6003412cu, 0x600340f0u, 0x600340b4u };
    static const u32 q_txbuf[27] = { 0x60033cd8u, 0x60033cd0u, 0x60033cc8u, 0x60033d20u, 0x60033d20u,
        0x60033d20u, 0x60033d20u, 0x60033d20u, 0x60033d20u, 0x60033d20u, 0x60033d18u, 0x60033d10u,
        0x60033d08u, 0x60033d00u, 0x60033cf8u, 0x60033cf0u, 0x60033ce8u, 0x60033d20u, 0x60033d20u,
        0x60033d20u, 0x60033d18u, 0x60033d10u, 0x60033d08u, 0x60033d00u, 0x60033cf8u, 0x60033cf0u, 0x60033ce8u };
    static const u32 q_link[27] = { 0x60034044u, 0x60034008u, 0x60033fccu, 0x60034260u, 0x60034260u,
        0x60034260u, 0x60034260u, 0x60034260u, 0x60034260u, 0x60034260u, 0x60034224u, 0x600341e8u,
        0x600341acu, 0x60034170u, 0x60034134u, 0x600340f8u, 0x600340bcu, 0x60034260u, 0x60034260u,
        0x60034260u, 0x60034224u, 0x600341e8u, 0x600341acu, 0x60034170u, 0x60034134u, 0x600340f8u, 0x600340bcu };
    static const u32 rate_clr[7] = { 0x60033d14u, 0x60033d0cu, 0x60033d04u, 0x60033cfcu,
        0x60033cf4u, 0x60033cecu, 0x60033ce4u };   /* .rodata.CSWTCH$51 */
    unsigned int queue = tx_queue & 0xffu, conf_addr, plcp0_addr, htsig_addr;
    unsigned int i, j, packet_num;
    unsigned char *packet0, *packet1, *packet2, *packet3;
    crypto_disable();
    if ((queue - 1) < 26u) {   /* bltu 26 lane */
        conf_addr = q_conf[queue - 1]; plcp0_addr = q_txbuf[queue - 1]; htsig_addr = q_link[queue - 1];
    } else {
        conf_addr = 0x60034258u; plcp0_addr = 0x60033d20u; htsig_addr = 0x60034260u;
    }
    /* Rate-clear: *(T51[rate-11]) = 0, else *(0x60033d1c) = 0 (shared store). */
    REG_WRITE(((tx_rate - 11) < 7u) ? rate_clr[tx_rate - 11] : 0x60033d1cu, 0);
    if (tx_rate > 15u) {   /* bltu 15 lane: HT-style big descriptor */
        u32 w = ((key_entry_no << 17) | 0x00200b000u | (bssid_no << 23) | (length & 0xfffu));
        REG_WRITE(conf_addr, w);
        if (queue <= 19u) {   /* bgeu 19 lane */
            REG_WRITE(0x60033c6cu, REG_READ(0x60033c6cu) & 0xfffffff0u);
        } else if (((tx_queue >> 8) & 0xffu) == 0) {
            u32 w1 = (((gi_bit >> 2) & 1u) << 30) | (gi_bit << 31) | 0x07000000u
                | (length & 0xfu) | (length << 8);
            REG_WRITE(htsig_addr, w1);
            REG_WRITE(0x60033c6cu, REG_READ(0x60033c6cu) & 0xfffffff0u);
        } else {
            u32 w1 = (((gi_bit >> 2) & 1u) << 30) | (gi_bit << 31) | 0x0f000000u
                | (length & 0xfu) | (length << 8);
            REG_WRITE(htsig_addr, w1);
            REG_WRITE(0x60033c6cu, 16);
        }
    } else {   /* legacy descriptor pair */
        REG_WRITE(conf_addr, (bssid_no << 23) | (key_entry_no << 17) | (tx_rate << 12) | (length & 0xfffu));
        REG_WRITE(htsig_addr, (((gi_bit >> 2) & 1u) << 30) | tx_rate | (gi_bit << 31) | (length << 8));
    }
    if ((psdu0_len | psdu1_len | psdu2_len | psdu3_len) == 0) {   /* beqz lane */
        REG_WRITE(plcp0_addr, TXBUF_START & 0xfffffu);
        return;
    }
    /* PSDU count select: psdu3?4 : psdu2?3 : psdu1?2 : 1. */
    packet_num = psdu3_len ? 4 : psdu2_len ? 3 : psdu1_len ? 2 : 1;
    {
        /* TX MAC descriptor header fill at TXBUF_START + PSDU_OFFSET[k]
         * (exact store offsets +0/+4/+8/+16/+20/+24/+32/+36/+40/+48 and
         * 0x80000000/0xc0000000 valid markers gated by remaining counts;
         * exact field packing approximate). */
        u32 *tb = (u32 *)(uintptr_t)TXBUF_START;
        tb[0] = (psdu0_len << 12) | psdu0_len | tx_rate;   /* +0 lane */
        tb[1] = link_start_addr;                            /* +4 lane */
        /* AP-MAC pack (6 bytes) + length/valid markers [approximate]: */
        tb[2] = (ap_mac_5 << 24) | (ap_mac_4 << 16) | (ap_mac_3 << 8) | ap_mac_2;
        tb[4] = (ap_mac_1 << 24) | (ap_mac_0 << 16) | 0x80000000u;
        tb[5] = (psdu1_len << 12) | psdu1_len;
        tb[6] = (psdu2_len << 12) | psdu2_len;
        tb[8] = (key_entry_no << 17) | (bssid_no << 23);
        tb[9] = gi_bit;
        tb[10] = PSDU0_OFFSET; tb[12] = PSDU1_OFFSET;
        (void)htsig_addr; (void)packet_num;
        /* Byte scatter loop over `length` source words: dest packet[k]
         * selected by cumulative psdu bounds (exact shape; dest bases and
         * third bound approximate). */
        {
            u32 *src = (u32 *)(uintptr_t)TXBUF_START;   /* exact base approximate */
            u32 rem = length;
            u32 b0 = psdu0_len, b1 = psdu0_len + psdu1_len, b2 = psdu0_len + psdu1_len + psdu2_len;
            packet0 = (unsigned char *)(uintptr_t)htsig_addr;
            packet1 = packet0 + 64; packet2 = packet1 + 64; packet3 = packet2 + 64;
            i = 0; j = 0;
            while (rem != 0) {   /* beq a4,a10 -> return */
                unsigned char b = (unsigned char)(src[i++] & 0xffu);
                if (j < b0) *packet0++ = b;
                else if (j < b1) *packet1++ = b;
                else if (j < b2) *packet2++ = b;
                else *packet3++ = b;
                j++; rem--;
            }
        }
    }
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

/* Undefined refs (9): PSDU0_OFFSET, PSDU1_OFFSET, PSDU2_OFFSET, PSDU3_OFFSET, TXBUF_START, crypto_disable, esp_dport_access_reg_read, ets_delay_us, phy_printf */