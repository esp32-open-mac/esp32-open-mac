/* Reconstruction of phy_chip_v7_ana.o (libphy.a)
 * CU: phy_chip_v7_ana.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/phy
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 101 | funcdb functions: 76
 * Disasm: re/esp32-phy/disasm/libphy/phy_chip_v7_ana.rdis
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
 * DPORT register reader; plain s32i/s8i to 0x3ffxxxxx/0x600xxxxx are writes. */
static inline unsigned reg_rd(unsigned addr);
static inline void reg_wr(unsigned addr, unsigned val);
#define REG_READ(a) reg_rd(a)
#define REG_WRITE(a, v) reg_wr((a), (v))
extern CriticalType phy_enter_critical_ret(void);  /* usage-typed: decl-only DIE says void */
extern void phy_exit_critical_to(CriticalType);
extern unsigned g_phyFuns[];  /* indirect-call table referenced via offsets */
/* Table-driven pbus/RF accessors. w46 = ram_pbus_force_test (proven via
 * gphyfuns_map.json slot pairing); w47/w55 unmapped -> symbolic. */
#define PBUS_W(w, a, b, c) (((void (*)(unsigned, unsigned, unsigned))g_phyFuns[(w)])( (a), (b), (c) ))
#define PBUS_FORCE_TEST(pbus_no, bus_en, cfg) ram_pbus_force_test((pbus_no), (bus_en), (cfg))

/* bb_bss_cbw40_ana phy_chip_v7_ana.c:706 @ phy_chip_v7_ana.o size 262B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40] x~8 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium-low - lane inventory + delta/select structure verified; exact per-lane constant mapping TODO (see rdis) */
void bb_bss_cbw40_ana(int cbw40)
{
    uint8 temp; (void)temp;           /* DWARF l708 */
    uint8 delta_tx, delta_rx;         /* DWARF l709-710 */
    uint8 rx_ext, dedge_rx;           /* DWARF l711-712 */
    extern U8 ana_byte84;             /* l8ui +84 source; exact symbol TODO */
    uint8 b = ana_byte84;
    delta_rx = (uint8)((b - (cbw40 ? 1 : 2)) & 0xffu);
    delta_tx = cbw40 ? 3 : 1;         /* moveqz lane */
    /* Lane inventory (all w40 = g_phyFuns[40], host 103; 4th arg & 0xff):
     * (103,1,3,delta_rx), (103,1,4,b), (103,1,10,b),
     * 20MHz lane: (103,1,1,((b2+10)|0x80)), (103,1,a14,...),
     * 40MHz lane: (103,1,1,((b2+10)|0x80)), (103,1,a14,((b-4)|0x80)),
     *             (103,1,a14,((b-4)|0x80)), (103,1,9,a5).
     * TODO: exact lane order/branch mapping from rdis. */
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 3, delta_rx);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 4, b);
    (void)delta_tx; (void)rx_ext; (void)dedge_rx;
}
/* bb_rst_en_set phy_chip_v7_ana.c:2314 @ phy_chip_v7_ana.o size 72B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d03c, 0x3ff5d040
 * Fidelity: high - bit-lane RMW pair verified per disasm */
void bb_rst_en_set(bool en)
{
    uint32 e = (uint32)(en & 0xffu);
    REG_WRITE(0x3ff5d03cu, (REG_READ(0x3ff5d03cu) & 0xbfffffffu) | ((e << 30) & 0x40000000u));
    REG_WRITE(0x3ff5d040u, (REG_READ(0x3ff5d040u) & 0x7fffffffu) | ((e << 31) & 0x80000000u));
}
/* bt_get_i2c_data phy_chip_v7_ana.c:1818 @ phy_chip_v7_ana.o size 1096B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[42], g_phyFuns[38] | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium-high - prologue hooks, chained lane sequence with exact per-lane constants, rd_en chaining, tail loop verified per disasm */
void bt_get_i2c_data(U8 * i2c_mst, U8 * i2c_block, U8 * i2c_addr, U8 * i2c_addr_tx, U8 * i2c_data_tx, U8 * i2c_addr_rx, U8 * i2c_data_rx, uint8 i2c_num, uint8 * i2c_rd_en)
{
    uint8 i; (void)i;                 /* DWARF l1824 */
    U8 ir_enx_cap; (void)ir_enx_cap;  /* DWARF l1832 */
    uint8 pll_rst_start; (void)pll_rst_start;  /* DWARF l1842 */
    ((void (*)(u32, u32, u32, u32))g_phyFuns[42])(98, 1, 0, 7);  /* +168 lane (a13/a14=7,a15=1 setup; upper-arg roles uncertain) */
    ((void (*)(u32, u32, u32))g_phyFuns[38])(98, 1, 0);          /* +152 lane */
    if (i2c_num == 0)   /* bne -> lane chain, else return */
        return;
    /* Chained lane sequence: lane k fills index k, then
     * `if (i2c_num <= k+1) return`, else i2c_rd_en[k+1] = 0 and fall
     * through to lane k+1. (Loop-top rd_en[i]=i + jx dispatch only
     * serves index 0 and the >=11 tail; chains bypass it.) */
    i = 0;
    i2c_rd_en[0] = 0;
    i2c_mst[0] = 0; i2c_block[0] = 99; i2c_addr[0] = 0; i2c_addr_tx[0] = 15;
    i2c_data_tx[0] = 0; i2c_data_rx[0] = 0; i2c_addr_rx[0] = 15;
    i2c_rd_en[0] = 1;
    if (i2c_num < 2) return;
    i2c_rd_en[1] = 0;
    i = 1;
    i2c_mst[1] = 1; i2c_block[1] = 98; i2c_addr[1] = 1; i2c_addr_tx[1] = 16;
    i2c_data_tx[1] = 0; i2c_data_rx[1] = 0; i2c_addr_rx[1] = 16;
    if (i2c_num < 3) return;
    i2c_rd_en[2] = 0;
    i = 2;
    i2c_mst[2] = 1; i2c_block[2] = 98; i2c_addr[2] = 2; i2c_addr_tx[2] = 17;
    i2c_data_tx[2] = 0; i2c_data_rx[2] = 0; i2c_addr_rx[2] = 17;
    if (i2c_num < 4) return;
    i2c_rd_en[3] = 0;
    i = 3;
    i2c_mst[3] = 0; i2c_block[3] = 99; i2c_addr[3] = 0; i2c_addr_tx[3] = 0;
    i2c_data_tx[3] = 7; i2c_data_rx[3] = 7; i2c_addr_rx[3] = 0;
    if (i2c_num < 5) return;
    i2c_rd_en[4] = 0;
    i = 4;
    i2c_mst[4] = 0; i2c_block[4] = 99; i2c_addr[4] = 3; i2c_addr_tx[4] = 22;
    i2c_data_tx[4] = 0; i2c_data_rx[4] = 0; i2c_addr_rx[4] = 22;
    if (i2c_num < 6) return;
    i2c_rd_en[5] = 0;
    i = 5;
    i2c_mst[5] = 0; i2c_block[5] = 99; i2c_addr[5] = 5; i2c_addr_tx[5] = 20;
    i2c_data_tx[5] = 0; i2c_data_rx[5] = 0; i2c_addr_rx[5] = 20;
    if (i2c_num < 7) return;
    i2c_rd_en[6] = 0;
    i = 6;
    i2c_mst[6] = 0; i2c_block[6] = 99; i2c_addr[6] = 4; i2c_addr_tx[6] = 21;
    i2c_data_tx[6] = 0; i2c_data_rx[6] = 0; i2c_addr_rx[6] = 21;
    if (i2c_num < 8) return;
    i2c_rd_en[7] = 0;
    i = 7;
    i2c_mst[7] = 0; i2c_block[7] = 99; i2c_addr[7] = 0; i2c_addr_tx[7] = 1;
    i2c_data_tx[7] = 23; i2c_data_rx[7] = 23; i2c_addr_rx[7] = 1;
    if (i2c_num <= 8) return;   /* bgeu 8 lane */
    i2c_rd_en[8] = 0;
    i = 8;
    i2c_mst[8] = 1; i2c_block[8] = 98; i2c_addr[8] = 0; i2c_addr_tx[8] = 2;
    i2c_data_tx[8] = 34; i2c_data_rx[8] = 34; i2c_addr_rx[8] = 2;
    if (i2c_num <= 9) return;
    i2c_rd_en[9] = 0;
    i = 9;
    i2c_mst[9] = 0; i2c_block[9] = 100; i2c_addr[9] = 4; i2c_addr_tx[9] = 24;
    i2c_data_tx[9] = 0; i2c_data_rx[9] = 0; i2c_addr_rx[9] = 24;
    if (i2c_num <= 10) return;
    i2c_rd_en[10] = 0;
    i = 10;
    i2c_mst[10] = 0; i2c_block[10] = 100; i2c_addr[10] = 7; i2c_addr_tx[10] = 25;
    i2c_data_tx[10] = 0; i2c_data_rx[10] = 0; i2c_addr_rx[10] = 25;
    if (i2c_num <= 11) return;
    i2c_rd_en[11] = 0;
    i = 11;   /* tail: blank lanes; loop-top sets rd_en[i]=i from here on */
    for (;;) {
        i2c_mst[i] = 0; i2c_block[i] = 0;
        i++;
        if (i >= i2c_num) return;   /* bgeu lane */
        i2c_rd_en[i] = i;
    }
}
/* bt_i2c_read_mem phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 143B [inferred]
 * Calls: phy_printf x3, esp_dport_access_reg_read x2 | Data refs: phy_printf | MMIO: 0x3ff4e0c0, 0x3ff4e0c4
 * Fidelity: medium - 3-iteration index program + read + diagnostic verified; fmt strings via rodata literals */
void bt_i2c_read_mem(void)
{
    phy_printf();                              /* opener diagnostic */
    for (uint8 i = 1; i <= 3; i++) {           /* bnei 3 lane */
        uint8 idx = (uint8)((i - 1) & 0xffu);
        REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffffff00u) | idx);
        uint32 v = REG_READ(0x3ff4e0c0u);
        (void)v;
        phy_printf();                          /* per-iter diagnostic */
    }
    phy_printf();                              /* closer diagnostic */
}
/* bt_i2c_read_set phy_chip_v7_ana.c:1340 @ phy_chip_v7_ana.o size 193B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x7 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e14c, 0x3ff4e150
 * Fidelity: high - full field-pack chain verified per disasm */
void bt_i2c_read_set(u8 i2c_mst, u8 i2c_block, u8 i2c_addr, u8 i2c_data_mask, bool i2c_rd_en, bool i2c_comp_en)
{
    uint8 mst = (uint8)(i2c_mst & 0xffu) & 0xfu;
    uint8 blk = (uint8)(i2c_block & 0xffu);
    uint8 adr = (uint8)(i2c_addr & 0xffu);
    uint8 dmask = (uint8)(i2c_data_mask & 0xffu);
    REG_WRITE(0x3ff4e14cu, (REG_READ(0x3ff4e14cu) & 0xfff0ffffu) |
                           ((uint32)mst << 16) | ((uint32)blk << 8));
    REG_WRITE(0x3ff4e14cu, (REG_READ(0x3ff4e14cu) & 0xffffff00u) | adr);
    REG_WRITE(0x3ff4e14cu, (REG_READ(0x3ff4e14cu) & 0xffff00ffu) | ((uint32)blk << 8));
    REG_WRITE(0x3ff4e14cu, (REG_READ(0x3ff4e14cu) & 0xffefffffu) |
                           ((uint32)(i2c_rd_en & 1u) << 20));
    REG_WRITE(0x3ff4e150u, (REG_READ(0x3ff4e150u) & 0xfffdffffu) |
                           ((uint32)(i2c_comp_en & 1u) << 17));
    REG_WRITE(0x3ff4e150u, (REG_READ(0x3ff4e150u) & 0xffffff00u) | dmask);
}
/* bt_i2c_set_wifi_data phy_chip_v7_ana.c:1472 @ phy_chip_v7_ana.o size 226B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e130, 0x3ff4e134, 0x3ff4e138 (+2 more staging regs)
 * Fidelity: medium - dispatch on (i>>2), per-byte bit-field insert into 0x3ff4e13x staging regs verified; exact field widths approximate */
void bt_i2c_set_wifi_data(U8 * data, U8 i2c_num)
{
    U8 i;   /* DWARF l1474 */
    if (i2c_num == 0)
        return;                                  /* beqz a3 -> return */
    for (i = 0; i < i2c_num; i++) {              /* counted loop over bytes */
        uint8 b = data[i];                       /* l8ui a6,a7,0 */
        switch ((i >> 2) & 0xff) {               /* srli a6,a3,2 dispatch */
        case 0: {                                /* 0x3ff4e130 */
            uint32 v = REG_READ(0x3ff4e130);
            v &= ~(0xffu << ((i * 8) & 31));     /* ssl/sll mask dance */
            v |= ((uint32)b << ((i * 8) & 31));
            REG_WRITE(0x3ff4e130, v);
            break;
        }
        case 1: {                                /* 0x3ff4e134 */
            uint32 v = REG_READ(0x3ff4e134);
            v &= ~(0xffu << (((i & 3) * 8) & 31));
            v |= ((uint32)b << (((i & 3) * 8) & 31));
            REG_WRITE(0x3ff4e134, v);
            break;
        }
        default: {                               /* 0x3ff4e138+ staging */
            REG_WRITE(0x3ff4e138, b);            /* approximate */
            break;
        }
        }
    }
}
/* bt_i2c_write_set phy_chip_v7_ana.c:1390 @ phy_chip_v7_ana.o size 1392B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x19 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e0c4, 0x3ff4e100, 0x3ff4e104, 0x3ff4e108, 0x3ff4e0d8, 0x3ff4e0dc, 0x3ff4e0e0, 0x3ff4e0e4, 0x3ff4e0e8, 0x3ff4e0ec, 0x3ff4e0f0, 0x3ff4e0f4, 0x3ff4e10c, 0x3ff4e110, 0x3ff4e128, 0x3ff4e12c, 0x3ff4e0d0, 0x3ff4e11c, 0x3ff4e0d4, 0x3ff4e120, 0x3ff4e124, 0x3ff4e0c8, 0x3ff4e0cc, 0x3ff4e114, 0x3ff4e118, 0x3ff4e164
 * Fidelity: medium - prologue/mask-loop, all 5 phase skeletons, lane dispatch keys, target regs, byte/nibble sources verified; phase-1 pointer-xor mask idiom reproduced exactly (intent unclear, see note); funnel widths approximate */
void bt_i2c_write_set(U8 * i2c_mst, U8 * i2c_block, U8 * i2c_addr, U8 * i2c_addr_tx, U8 * i2c_data_tx, U8 * i2c_addr_rx, U8 * i2c_data_rx, U8 i2c_num, U8 * i2c_rd_en)
{
    U8 i; (void)i;                        /* DWARF l1392 */
    u32 rd_en_data = 0;                   /* DWARF l1396 */
    U8 k;
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffff83ffu) | (((u32)i2c_num & 0x1fu) << 10));
    if (i2c_num == 0) {   /* beqz -> tail store + return */
        REG_WRITE(0x3ff4e164u, i2c_num);
        return;
    }
    for (k = 0; k < i2c_num; k++)   /* rd_en bitmask loop */
        if (i2c_rd_en[k] == 1)
            rd_en_data |= (u32)1 << k;
    REG_WRITE(0x3ff4e164u, rd_en_data);
    /* Phase 1: per-lane RMW to 0x3ff4e100/104/108 by (i>>3). Mask idiom
     * (verified exact): m = rd_en_end ^ (i2c_num << (i*4));
     * REG = (read & m) | ((nibble) << (i*4)). The pointer-derived mask
     * keeps the high address bits; intent unclear but reproduced exactly. */
    {
        U8 *rd_end = i2c_rd_en + i2c_num;
        for (i = 0; i < i2c_num; i++) {
            u32 addr = (i >> 3) == 0 ? 0x3ff4e100u : (i >> 3) == 1 ? 0x3ff4e104u : 0x3ff4e108u;
            u32 v = REG_READ(addr);
            u32 m = (u32)(uintptr_t)rd_end ^ ((u32)i2c_num << ((i * 4) & 31));
            u32 nib = (i >> 3) == 0 ? (i2c_mst[i] & 0xfu)
                : (i >> 3) == 1 ? (i2c_mst[i] & 0x7u) : (i2c_mst[i] & 0x7u);
            v = (v & m) | (nib << ((i * 4) & 31));   /* exact shape; nibble width approximate */
            REG_WRITE(addr, v);
        }
    }
    /* Phase 2: per-lane byte-pack to 0x3ff4e0d8..0x3ff4e10c by (i>>1),
     * default 0x3ff4e110. REG = (read & ~(0xffff << s)) | ((((addr[i])<<8)|block[i]) << s). */
    {
        static const u32 regs[9] = { 0x3ff4e0d8u, 0x3ff4e0dcu, 0x3ff4e0e0u, 0x3ff4e0e4u,
            0x3ff4e0e8u, 0x3ff4e0ecu, 0x3ff4e0f0u, 0x3ff4e0f4u, 0x3ff4e10cu };
        for (i = 0; i < i2c_num; i++) {
            u32 idx = (u32)i >> 1;
            u32 addr = idx <= 8 ? regs[idx] : 0x3ff4e110u;
            u32 v = REG_READ(addr);
            u32 s = (idx <= 8 ? (u32)(i * 4) : (u32)(i & 1) * 16) & 31;   /* approximate */
            u32 field = (((u32)i2c_addr[i] << 8) | i2c_block[i]) & 0xffffu;
            v = (v & ~(0xffffu << s)) | (field << s);
            REG_WRITE(addr, v);
        }
    }
    /* Phase 3: per-lane 0x3ff4e128/0x3ff4e12c bit RMWs + (i>>3) switch to
     * 0x3ff4e0d0/0x3ff4e0d4/0x3ff4e124 (each with a secondary RMW to
     * 0x3ff4e11c/0x3ff4e120/0x3ff4e124) with nibble insert. */
    for (i = 0; i < i2c_num; i++) {
        u32 v = REG_READ(0x3ff4e128u);
        v = (v & ~1u) | ((i2c_addr_rx[i] >> 4) & 1u);
        REG_WRITE(0x3ff4e128u, v);
        v = REG_READ(0x3ff4e12cu);
        v = (v & ~1u) | ((i2c_addr_tx[i] >> 4) & 1u);   /* approximate */
        REG_WRITE(0x3ff4e12cu, v);
        {
            u32 addr = (i >> 3) == 0 ? 0x3ff4e0d0u : (i >> 3) == 1 ? 0x3ff4e0d4u : 0x3ff4e124u;
            u32 addr2 = (i >> 3) == 0 ? 0x3ff4e11cu : (i >> 3) == 1 ? 0x3ff4e120u : 0x3ff4e124u;
            u32 sh = ((i & 7) * 4) & 31;   /* slli-2 funnel; approximate */
            v = REG_READ(addr);
            v = (v & ~(0xfu << sh)) | (((u32)i2c_addr_rx[i] & 0xfu) << sh);
            REG_WRITE(addr, v);
            v = REG_READ(addr2);
            v = (v & ~(0xfu << sh)) | (((u32)i2c_addr_tx[i] & 0xfu) << sh);
            REG_WRITE(addr2, v);
        }
    }
    /* Phase 4: per-lane double switch on (addr_rx[i]>>2)/(addr_tx[i]>>2)
     * selecting 0x3ff4e0c8/0x3ff4e0cc/0x3ff4e114/0x3ff4e118; shared funnel
     * body inserts the low 2-bit field + data byte. */
    for (i = 0; i < i2c_num; i++) {
        static const u32 regs[4] = { 0x3ff4e0c8u, 0x3ff4e0ccu, 0x3ff4e114u, 0x3ff4e118u };
        u32 sel = (i2c_addr_rx[i] >> 2) & 3u;
        u32 v = REG_READ(regs[sel]);
        u32 sh = ((i2c_addr_rx[i] & 3u) << 3) & 31;
        v = (v & ~(0xffu << sh)) | (((u32)i2c_data_rx[i] << 0) & (0xffu << sh));   /* approximate */
        REG_WRITE(regs[sel], v);
        sel = (i2c_addr_tx[i] >> 2) & 3u;
        v = REG_READ(regs[sel]);
        sh = ((i2c_addr_tx[i] & 3u) << 3) & 31;
        v = (v & ~(0xffu << sh)) | (((u32)i2c_data_tx[i] << 0) & (0xffu << sh));   /* approximate */
        REG_WRITE(regs[sel], v);
    }
}
/* bt_track_pll_cap phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 106B [inferred]
 * Calls: phy_enter_critical, esp_dport_access_reg_read, phy_dis_hw_set_freq, pll_correct_dcap, bt_track_tx_power, phy_en_hw_set_freq, phy_exit_critical | Data refs: (flag bytes via literals) | MMIO: 0x3ff4e168, 0x3ff5d008
 * Fidelity: medium - gate chain + call sequence verified; flag symbols TODO */
void bt_track_pll_cap(void)
{
    extern U8 trk_arm, trk_en2, trk_en3, trk_en4;   /* exact symbols TODO */
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    if (!trk_arm)                                  /* beqz lane */
        goto out;
    if (!(REG_READ(0x3ff5d008u) & 0x20000000u))    /* bbci 29 lane */
        goto out;
    if (trk_en2)                                   /* bnez lane */
        goto out;
    if (trk_en3)                                   /* bnez lane */
        goto out;
    {
        uint8 est = (uint8)((REG_READ(0x3ff4e168u) >> 24) & 0x7fu);  /* extui 24,7 */
        phy_dis_hw_set_freq();                     /* local direct call8 */
        uint8 cap = 0;                             /* stack lane */
        /* r = pll_correct_dcap(est, &cap, trk_en3); a10/a11/a12 lanes */
        uint8 r = (uint8)pll_correct_dcap(est, &cap, trk_en3);
        if (trk_en4) {                             /* beqz -> skip tx_power */
            bt_track_tx_power(est, (sint8)r);      /* a10=est,a11=sext(r) */
        }
    }
    phy_en_hw_set_freq();                          /* local direct call8 */
out:
    phy_exit_critical_to(crit);
}
/* bt_track_tx_power phy_chip_v7_ana.c:1645 @ phy_chip_v7_ana.o size 59B [dwarf-sig]
 * Calls: btpwr_tsens_track, btpwr_pll_track, bt_tx_gain_cal_set | Data refs: (none) | MMIO: (none)
 * Fidelity: medium-low - gate structure, local direct calls (via .rela.iram1 SLOT0_OP), cache-store verified; flag symbol + gain-cal args approximate */
void bt_track_tx_power(uint8 freq, sint8 cap_delta)
{
    /* NOTE: bare `call8` insns here are local direct calls resolved through
     * .rela.iram1 (funcdb calls[] missed them); header lists them. */
    extern U8 pll_track_enable_flag;   /* l8ui gate; exact symbol TODO */
    extern void bt_tx_gain_cal_set3(uint8 v, sint8 d, uint32 x);  /* usage-inferred arity */
    uint8 tsens = (uint8)(btpwr_tsens_track() & 0xff);  /* a10 extui lane */
    (void)tsens;
    uint8 pll = 0;
    if (cap_delta != 0 && !pll_track_enable_flag)
        pll = (uint8)btpwr_pll_track(freq, cap_delta);  /* sint8 ret, extui */
    extern U8 gain_cache_flag;         /* 2nd l8ui lane; exact symbol TODO */
    if (gain_cache_flag != pll) {
        gain_cache_flag = pll;         /* s8i; memw */
        bt_tx_gain_cal_set3(pll, cap_delta, 0);  /* a12 lane approximate */
    }
}
/* btpwr_pll_track phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 109B [inferred]
 * Calls: esp_dport_access_reg_read x2 | Data refs: (flag bytes via literals) | MMIO: 0x3ff4e0c0, 0x3ff4e0c4
 * Fidelity: medium - cache gate, 3x-index program, accumulate, cap adjust law verified; flag symbols TODO, delta param unused (overwritten) */
sint8 btpwr_pll_track(uint8 freq, sint8 pll_cap_delta)
{
    /* NOTE: pll_cap_delta (callee a3) is overwritten by a flag-address load
     * and never used — vestigial, like ram_iq_est_enable params. */
    (void)pll_cap_delta;
    extern U8 f_freq, f_val, f_cnt, f_ref;   /* exact symbols TODO */
    extern sint16 f_sum;                     /* l16si/s16i lane */
    uint8 f = (uint8)(freq & 0xffu);
    if (f_freq != f) {
        uint8 idx = (uint8)((f * 3) & 0xffu);    /* addx2; extui */
        REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffffff00u) | idx);
        int32 v = (int32)REG_READ(0x3ff4e0c0u);
        f_sum = (sint16)(f_sum + (v >> 24));     /* srai 24 accumulate */
        f_freq = f;
        f_val = (uint8)((f_cnt + 1) & 0xffu);    /* counter lane */
        f_cnt = f_val;
        if (f_val > 15) {                        /* bgeu 15 -> ret cached */
            int16 raw = (sint16)((f_sum + 8) >> 4);
            if ((sint8)f_ref == (sint8)raw) {
                f_sum = 0;                       /* 8a4 clear path */
                f_ref = 0;
                return (sint8)f_val;
            }
            int16 cap = raw;
            uint8 vv;
            if (cap < 2)
                vv = (cap >= -1) ? 0 : (uint8)(((cap * 3) * 2) & 0xffu);
            else
                vv = (uint8)((cap << 3) & 0xffu);
            int8 s = (int8)vv;
            if (s <= 24)
                vv = (uint8)(s < -18 ? -18 : s);
            f_val = (uint8)raw;                  /* s8i raw lane */
            return (sint8)vv;
        }
    }
    return (sint8)f_val;
}
/* btpwr_tsens_track phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 109B [inferred]
 * Calls: tsens_code_read (local direct call8 via .rela.iram1) | Data refs: (flag bytes via literals) | MMIO: (none direct)
 * Fidelity: medium - delta/slew structure, mulsh scale, +/-24 clamp verified; flag symbols TODO */
sint16 btpwr_tsens_track(void)
{
    extern U8 t_cache, t_armed, t_cur, t_ref;   /* exact symbols TODO */
    uint8 tsens = tsens_code_read();            /* a10 return lane */
    uint16 d = (uint16)((tsens - t_cache + 5) & 0xffffu);
    t_armed = 1;                                /* s8i 1 lane */
    uint8 cur = t_cur;
    if (d <= 10) {                              /* bgeu 10,d -> small path */
        int8 c = (int8)cur;                     /* sext 7 */
        if (c > 24)                             /* blt 24,c -> return 24 */
            return 24;
        return (c < -24) ? -24 : c;             /* max -24 */
    }
    /* Slew path: scaled fresh delta, update cache. */
    int32 diff = (int32)t_ref - (int32)tsens;
    int32 hi = (int32)(((int64)diff * (int32)0x92492493ll) >> 32);
    int32 v = ((diff + hi) >> 2) - (diff >> 31);
    t_cache = tsens;                            /* s8i update lane */
    if (v > 24)
        return 24;
    return (sint16)(v < -24 ? -24 : v);
}
/* chan_to_freq phy_chip_v7_ana.c:728 @ phy_chip_v7_ana.o size 54B [dwarf-sig]
 * Calls: phy_printf (invalid-channel lane) | Data refs: phy_printf | MMIO: (none)
 * Fidelity: high - 2.4GHz band law fully verified (2412+5*(ch-1), 2484 for ch14) */
uint16 chan_to_freq(int8 channel)
{
    int8 ch = channel;                       /* sext a11,a2,7 */
    if (ch == 0 || ch > 14) {                /* beqz / blt 14 */
        phy_printf();                        /* diagnostic on invalid lane */
        return 0x96cu;                       /* 2412 default */
    }
    if (ch == 14)
        return 0x9b4u;                       /* 2484 */
    return (uint16)(0x96cu + 5u * (uint16)(ch - 1));  /* addx4 lane; extui 16 */
}
/* check_rfpll_write_i2c phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 106B [inferred]
 * Calls: bt_get_i2c_data, (indirect) g_phyFuns[38], phy_printf | Data refs: bt_get_i2c_data, phy_printf | MMIO: (none direct)
 * Fidelity: medium-low - table-build + walk/compare loop + diagnostic verified; table contents TODO */
void check_rfpll_write_i2c(void)
{
    U8 tab_a[32], tab_b[32], tab_c[32];   /* stack tables (sizes approx) */
    (void)tab_a; (void)tab_b; (void)tab_c;
    /* Stage 11-entry expectation tables, then: */
    bt_get_i2c_data(NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL);  /* args TODO */
    /* Walk compare loop (bne-bounded): per lane w38 hook + check. */
    for (int i = 0; i < 11; i++) {        /* trip count per staging */
        ((void (*)(void))g_phyFuns[38])();  /* +152 lane; args TODO */
        /* TODO: compare readback vs expectation lane. */
    }
    phy_printf();                         /* diagnostic tail */
}
/* chip_v7_adc_wr_dly phy_chip_v7_ana.c:890 @ phy_chip_v7_ana.o size 94B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40], g_phyFuns[42] | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: high - bit-pack + two ordered writes verified per disasm */
void chip_v7_adc_wr_dly(uint8 dly1, uint8 dly2, uint8 dly3, uint8 dly4, uint8 dly5, uint8 dly6)
{
    uint8 p1 = (uint8)(((dly2 << 2) | dly1) | (dly3 << 4) | (dly4 << 6));
    /* slli/extui/or lane: ((dly2<<2|dly1)|(dly3<<4)|(dly4<<6)) & 0xff */
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(102, 4, 8, p1);
    uint8 p2 = (uint8)(((dly6 << 2) | dly5) & 0xffu);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (102, 4, 9, 3, 0, p2);
}
/* chip_v7_rxmax_ext_ana phy_chip_v7_ana.c:647 @ phy_chip_v7_ana.o size 154B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[41], get_lna_vga_dcap_val, g_phyFuns[40] | Data refs: g_phyFuns, get_lna_vga_dcap_val | MMIO: (none direct)
 * Fidelity: medium - branch/select structure + pack lanes verified; w41 trailing arg (stale a15) approximate */
void chip_v7_rxmax_ext_ana(uint8 ext_level)
{
    uint8 el = (uint8)(ext_level & 0xffu);
    sint16 rxv[2];                            /* stack l16ui pair */
    /* pll_cap = g_phyFuns[41](98, 1, 5, 7, 0); a15 lane stale in disasm. */
    uint8 pll_cap = (uint8)((uint32 (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[41])(98, 1, 5, 7, 0);
    get_lna_vga_dcap_val(pll_cap, rxv);        /* a10=ret, a11=stack */
    int16 r0 = (int16)rxv[0], r1 = (int16)rxv[1];
    if (el >= 3) {                             /* bltui 3 -> else */
        int16 base = (r0 < 8) ? 8 : (int16)0xfff8;
        uint8 v = (uint8)(((64 | (base + r0)) & 0xffu));
        ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(100, 0, 4, v);
    } else {
        ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(100, 0, 4, (uint8)((r0 | 64) & 0xffu));
    }
    if (el == 2) {                             /* bnei -> skip */
        int16 base = (r1 < 8) ? 8 : (int16)0xfff8;  /* blt 8 lane */
        r1 = (int16)(base + r1);
    }
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(100, 0, 7, (uint8)(((r1 | 64)) & 0xffu));
}
/* chip_v7_set_chan phy_chip_v7_ana.c:828 @ phy_chip_v7_ana.o size 35B [dwarf-sig]
 * Calls: chip_sleep_prot_dis, chip_v7_set_chan_nomac, chip_sleep_prot_en | Data refs: chip_sleep_prot_dis, chip_sleep_prot_en, chip_v7_set_chan_nomac | MMIO: (none)
 * Fidelity: high - 3-call wrapper verified per disasm */
void chip_v7_set_chan(int8 channel, int8 sub_chan_cfg)
{
    chip_sleep_prot_dis();
    chip_v7_set_chan_nomac((int8)channel, (int8)sub_chan_cfg);  /* extui+sext arg prep */
    chip_sleep_prot_en();
}
/* chip_v7_set_chan_ana phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 35B [dwarf-sig]
 * Calls: set_channel_rfpll_freq | Data refs: chip7_phy_init_ctrl, chip7_sleep_params (relocs) | MMIO: (none)
 * Fidelity: high - call + shadow store verified per disasm + relocs */
void chip_v7_set_chan_ana(int8 channel)
{
    extern uint8 chip7_sleep_params[];
    extern uint8 chip7_phy_init_ctrl[];   /* l8ui +1 source */
    set_channel_rfpll_freq(channel, chip7_phy_init_ctrl[1], 0);  /* a12=0 lane */
    chip7_sleep_params[81] = (uint8)channel;   /* s8i lane */
}
/* chip_v7_set_chan_nomac phy_chip_v7_ana.c:774 @ phy_chip_v7_ana.o size 234B [dwarf-sig]
 * Calls: disable_wifi_agc, phy_enter_critical, set_channel_rfpll_freq, bb_bss_cbw40, chip_v7_set_chan_misc, phy_exit_critical, chan14_mic_cfg, phy_wifi_bb_reset, enable_wifi_agc | Data refs: bb_bss_cbw40, chan14_mic_cfg, chan14_mic_en, chip7_phy_init_ctrl, chip7_sleep_params, chip_v7_set_chan_misc, disable_wifi_agc, enable_wifi_agc, g_phyFuns, phy_dis_pwdet_one, phy_enter_critical, phy_exit_critical, phy_freq_offset, phy_wifi_bb_reset, set_channel_rfpll_freq | MMIO: 0x60033c00
 * Fidelity: medium - full call sequence, branch structure (bw40 select, chan-14 special), MMIO addr verified per disasm + relocs; struct field names unknown so byte offsets are used */
void chip_v7_set_chan_nomac(int8 channel, int8 sub_chan_cfg)
{
    u32 t0; (void)t0;                       /* DWARF l776 */
    sint16 freq_offset;                     /* DWARF l779 */
    uint16 freq;                            /* DWARF l780 */
    CriticalType crit_level;                /* DWARF l792 */
    extern uint8 chip7_sleep_params[];      /* per funcdb refs; layout unknown */
    extern uint8 chan14_mic_en;             /* flag byte tested before mic cfg */
    extern uint16 phy_freq_offset;          /* l16si source; per funcdb refs */
    extern CriticalType phy_enter_critical(void);  /* local decl-only DIE says void,
        but disasm uses its a2 return as crit_level -> true proto returns a value */
    /* Sleep-protect handshake: stash channel, raise flag, then read freq. */
    (void)REG_READ(0x60033c00);             /* l32r absolute; l32i + memw */
    chip7_sleep_params[81] = (uint8)channel;/* s8i a2,a6,81 */
    chip7_sleep_params[0] = 1;              /* s8i 1 after nop pad */
    freq = phy_freq_offset;                         /* l16si from literal */
    freq_offset = (sint16)freq;             /* same reg reused as callee a4; DWARF keeps both names */
    disable_wifi_agc();
    crit_level = phy_enter_critical();
    freq = set_channel_rfpll_freq(channel, chip7_sleep_params[1], freq_offset);
    /* 20/40MHz BB selection driven by signed sub_chan_cfg + shadow byte 83. */
    if (sub_chan_cfg >= 4) {                /* blti a4,4 -> else */
        bb_bss_cbw40((int8)chip7_sleep_params[83]);
    } else if ((int8)chip7_sleep_params[83] != sub_chan_cfg) {
        bb_bss_cbw40(sub_chan_cfg);         /* spill/flag dance per disasm */
        chip7_sleep_params[83] = (uint8)sub_chan_cfg;
    }
    /* Indirect tail through g_phyFuns table word 25 (l32i a3,a3,100; callx8 a3);
     * exact target/args uncertain (candidates: phy_dis_pwdet_one, chip7_phy_init_ctrl hook). */
    ((void (*)(void))g_phyFuns[25])();      /* approximate; see disasm */
    chip_v7_set_chan_misc(channel);
    phy_exit_critical();
    if (chan14_mic_en) {                    /* l8ui flag; beqz -> skip */
        if (channel == 14)
            chan14_mic_cfg(1);
        else
            chan14_mic_cfg(0);
    }
    phy_wifi_bb_reset();
    enable_wifi_agc();
}
/* chip_v7_set_chan_offset phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 106B [dwarf-sig]
 * Calls: phy_enter_critical, phy_freq_correct_opt, set_channel_rfpll_freq, bb_bss_cbw40, phy_exit_critical | Data refs: (sleep bytes/static via literals) | MMIO: (none)
 * Fidelity: high - store/accumulate/call sequence verified per disasm + relocs */
void chip_v7_set_chan_offset(sint16 freq_offset)
{
    extern uint8 chip7_sleep_params[];
    extern sint16 freq_offset_store;   /* s16i/l16si lane; exact symbol TODO */
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    int16 off = (int16)freq_offset;              /* sext 15 */
    freq_offset_store = off;                     /* s16i lane */
    if (chip7_sleep_params[78]) {                /* l8ui 78; beqz skip */
        int8 adj = (int8)chip7_sleep_params[79]; /* sext 7 */
        freq_offset_store = (sint16)(off + 8 * adj);  /* addx8 lane */
    }
    phy_freq_correct_opt();
    /* set_channel_rfpll_freq(sext(sleep[81]), sleep[1], stored). */
    set_channel_rfpll_freq((int8)chip7_sleep_params[81],
                           chip7_sleep_params[1], freq_offset_store);
    bb_bss_cbw40((int8)chip7_sleep_params[83]);  /* sext lane */
    phy_exit_critical_to(crit);                  /* mov a10,a5 lane */
}
/* correct_rfpll_offset phy_chip_v7_ana.c:1171 @ phy_chip_v7_ana.o size 263B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x4 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e0c0, 0x3ff4e0c4, 0x3ff4e148
 * Fidelity: medium - crystal scale law, compare-and-skip, strobe program loop verified; count-lane arithmetic approximate */
void correct_rfpll_offset(sint16 freq_offset, uint8 crystal_select)
{
    sint16 off = freq_offset;                    /* sext 15 */
    uint8 xtal = (uint8)(crystal_select & 0xffu);
    int32 v;
    if (xtal == 0)
        v = (int16)(((off + 8 * off) >> 2) & 0xffff);   /* addx8; srai 2 */
    else
        v = (int16)(((3 * off + 24 * off) >> 3) & 0xffff); /* addx2; addx8; srai 3 */
    extern sint16 stored_rf_offset;              /* l16si compare lane */
    if (v == stored_rf_offset) {                 /* bne -> correct lane */
        stored_rf_offset = (sint16)v;            /* 131 lane: store + return */
        return;
    }
    extern U8 corr_mode_flag;                    /* movnez source */
    uint8 count = corr_mode_flag ? 14 : 85;
    uint8 i = 0;
    int16 delta = (int16)(v - stored_rf_offset); /* sub lane; spill sp+4 */
    (void)delta;
    do {
        /* per-iter program word: (i<12) ? (15*i+37)&0xff : 253 */
        uint8 prog = (i < 12) ? (uint8)((15u * i + 37u) & 0xffu) : 253;
        uint32 r = REG_READ(0x3ff4e0c4u);
        REG_WRITE(0x3ff4e0c4u, (r & 0xffffff00u) | prog);
        uint32 d = REG_READ(0x3ff4e0c0u);
        REG_WRITE(0x3ff4e148u, (d & 0xffffffu) | ((r & 0xff000000u)));
        r = REG_READ(0x3ff4e0c4u);
        REG_WRITE(0x3ff4e0c4u, r | 0x200u);       /* strobe */
        r = REG_READ(0x3ff4e0c4u);
        REG_WRITE(0x3ff4e0c4u, r & ~0x200u);      /* 0xfffffdff */
        i++;
    } while (i != count);                        /* beq count,i -> exit */
    stored_rf_offset = (sint16)v;                /* s16i store-back */
}
/* force_txrxoff phy_chip_v7_ana.c:164 @ phy_chip_v7_ana.o size 181B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff460a0
 * Fidelity: high - set/clear lanes with interleaved 1us delays verified */
void force_txrxoff(bool off_en)
{
    if (!(off_en & 0xffu)) {                     /* beqz -> clear lane */
        REG_WRITE(0x3ff460a0u, REG_READ(0x3ff460a0u) & 0xfffff3ffu);
        REG_WRITE(0x3ff460a0u, REG_READ(0x3ff460a0u) & 0xfffffcffu);
        REG_WRITE(0x3ff460a0u, REG_READ(0x3ff460a0u) & 0xffffcfffu);
        return;
    }
    REG_WRITE(0x3ff460a0u, (REG_READ(0x3ff460a0u) & 0xffffcfffu) | 0x2000u);
    ets_delay_us(1);
    REG_WRITE(0x3ff460a0u, (REG_READ(0x3ff460a0u) & 0xfffff3ffu) | 0x800u);
    ets_delay_us(1);
    REG_WRITE(0x3ff460a0u, (REG_READ(0x3ff460a0u) & 0xfffffcffu) | 0x200u);
    ets_delay_us(1);
}
/* freq_write_wifi_chan phy_chip_v7_ana.c:2366 @ phy_chip_v7_ana.o size 164B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, write_wifi_chan_data, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us, write_wifi_chan_data | MMIO: 0x3ff4e0c4
 * Fidelity: medium - main lane fully verified; bgez recovery lane (re-program + bany retry) TODO */
void freq_write_wifi_chan(uint8 chan_freq)
{
    uint8 ch = (uint8)(chan_freq & 0xffu);           /* extui lane */
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xe7ffffffu) | 0x10000000u);
    write_wifi_chan_data(ch);
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffffff00u) | ((uint8)((ch << 1) & 0xffu)));
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) | 0x100u);
    ets_delay_us(2);
    if ((int32)REG_READ(0x3ff4e0c4u) >= 0) {         /* bgez -> main finish */
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & ~0x100u);   /* 0xfffffeff */
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & 0xe7ffffffu);
        return;
    }
    /* TODO recovery lane at +0x96: write_wifi_chan_data(addr-derived index),
     * bany-gated retry, odd `j a1` tail. See rdis. */
}
/* get_i2c_read_mask phy_chip_v7_ana.c:36 @ phy_chip_v7_ana.o size 26B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (rodata mask table via literal) | MMIO: (none)
 * Fidelity: high - index math + table lookup verified; table entries quoted */
uint32 get_i2c_read_mask(uint8 block)
{
    /* rodata u32 table (12 entries): 3ff4e130, ffff00ff, 3ff4e0c4, 3ff4e0c0,
     * 00ffff00, 3ff4e148, ... (see .iram1 literals after function). */
    extern const uint32 i2c_block_mask_table[12];
    uint8 i = (uint8)(block - 98);   /* addi -98; extui */
    if (i > 11)                      /* bltu 11,i -> return 0 */
        return 0;
    return i2c_block_mask_table[i];  /* addx4; l32i */
}
/* get_i2c_write_data phy_chip_v7_ana.c:991 @ phy_chip_v7_ana.o size 48B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none - pure buffer staging)
 * Fidelity: high - 4 masked stores verified per disasm. NOTE: 6th param is
 * used as a base POINTER (add a7,a7,index; s8i) though the decl DIE says
 * plain uint8 — probable header/DWARF imprecision; cast used below. */
void get_i2c_write_data(uint8 index, uint8 block, uint8 host_id, uint8 reg_add, uint8 pData, uint8 block_m, uint8 * host_id_m, uint8 * reg_add_m, uint8 * pData_m)
{
    host_id_m[index] = host_id;   /* s8i a4,a9,0; a9 = host_id_m+index */
    reg_add_m[index] = reg_add;   /* s8i a5,a8,0 */
    ((uint8 *)(uintptr_t)block_m)[index] = block;  /* s8i a3,a7,0; a7 as base */
    pData_m[index] = pData;       /* s8i a6,a2,0 */
}
/* get_lna_vga_dcap_val phy_chip_v7_ana.c:637 @ phy_chip_v7_ana.o size 80B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[11] x2 | Data refs: g_phyFuns (literal reloc R_XTENSA_32) | MMIO: (none)
 * Fidelity: high - every insn accounted; fixed-point scale constants + hook slot verified via relocs */
void get_lna_vga_dcap_val(uint16 pll_cap, sint16 * rfrx_cap)
{
    sint16 lna_cap;   /* DWARF l639 */
    sint16 vga_cap;   /* DWARF l639 */
    /* Helper: GCC strength-reduced signed scale: (mulsh(t,C)>>5) - (t>>31). */
    uint32 p = (uint32)(pll_cap & 0xffffu);            /* extui a2,a2,0,16 */
    int32 t1 = (int32)(24u * p - 340u);                /* addx2; slli 3; +0xfffffeac */
    int32 s1 = (int32)(((int64)t1 * (int32)0x24168e19ll >> 32) >> 5) - (t1 >> 31);
    /* hook = *(g_phyFuns+44); args (s,15,0); return -> caller a10. */
    lna_cap = (sint16)(int32)((int32 (*)(int32, uint32, uint32))g_phyFuns[11])(s1, 15, 0);
    int32 t2 = (int32)(23u * p + 29u);                 /* sub a4,a4,a2; addi 29 */
    int32 s2 = (int32)(((int64)t2 * (int32)0x27932b49ll >> 32) >> 5) - (t2 >> 31);
    vga_cap = (sint16)(int32)((int32 (*)(int32, uint32, uint32))g_phyFuns[11])(s2, 15, 0);
    rfrx_cap[0] = lna_cap;                             /* s16i a10,a3,0 */
    rfrx_cap[1] = vga_cap;                             /* s16i a10,a3,2 */
}
/* get_rf_freq_cap phy_chip_v7_ana.c:1142 @ phy_chip_v7_ana.o size 163B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[56,60,58,57,59,41,38] | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium - ordered hook sequence + cap_array pack lanes verified; w56 arity (no arg setup) as-is */
void get_rf_freq_cap(uint16 freq, sint16 freq_offset, uint8 * x_reg, uint8 * cap_array)
{
    ((void (*)(void))g_phyFuns[56])();   /* +224 lane; no arg setup */
    extern U8 rfcap_mode_flag;   /* l8ui +1 lane; exact symbol TODO */
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[60])
        (freq & 0xffffu, rfcap_mode_flag, (uint32)(freq_offset & 0xffffu), (uint32)(uintptr_t)x_reg);
    ((void (*)(uint32))g_phyFuns[58])((uint32)(uintptr_t)x_reg);
    ((void (*)(uint32))g_phyFuns[57])((uint32)(uintptr_t)x_reg);
    ((void (*)(uint32))g_phyFuns[59])((uint32)(uintptr_t)x_reg);
    /* cap_array[0] = g_phyFuns[41](98,1,5,7,0) low byte; a15 lane stale. */
    cap_array[0] = (uint8)((uint32 (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[41])(98, 1, 5, 7, 0);
    uint32 r38 = ((uint32 (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[38])(98, 1, 6, 3, 0);
    cap_array[1] = (uint8)((r38 | 0x80u) & 0xffu);  /* and -16 / or -128 lane */
}
/* get_rf_freq_init phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 19B [dwarf-sig-decl]
 * Calls: get_rf_freq_init$part$2 (local) | Data refs: (init flag word) | MMIO: (none)
 * Fidelity: medium - flag-gated part call verified; flag symbol TODO */
void get_rf_freq_init(void)
{
    extern uint32 rf_init_flagword2;   /* bbsi bit4 lane; exact symbol TODO */
    if (rf_init_flagword2 & 0x10u)     /* bbsi -> skip (already inited) */
        return;
    get_rf_freq_init$part$2();
}
/* get_rf_freq_init$part$2 phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 315B [dwarf-sig-base-decl]
 * Calls: get_rf_freq_cap, get_rfrx_dcap_bt x2, wr_rf_freq_mem | Data refs: get_rf_freq_cap, get_rfrx_dcap_bt, wr_rf_freq_mem | MMIO: (none direct; via callees)
 * Fidelity: medium-low - I2C prologue, per-channel cap/dcap/fetch loop, init-done flag verified; table geometry approximate */
void get_rf_freq_init$part$2(void)
{
    extern uint32 rf_init_flagword;   /* |= 16 at exit; exact symbol TODO */
    extern U8 rf_chan_count_flag;     /* loop bound sp+32 source; TODO */
    /* Prologue: w42 (98,1,2,7,0,0)-ish, w42 (98,1,2,...), w38 (104,...),
     * w38-combine loop. TODO: exact prologue ops from rdis. */
    uint8 n = 0;
    uint16 freq = 0x96cu;                        /* 2412 start */
    uint8 bound = rf_chan_count_flag ? 14 : 85;  /* movnez lane (85/14) */
    do {
        uint8 x_reg[4]; (void)x_reg;
        uint8 caps[4]; (void)caps;
        /* get_rf_freq_cap(freq, ...); get_rfrx_dcap_bt x2; wr_rf_freq_mem */
        n++;
        freq = (uint16)(freq + 5);               /* addi 5 lane */
    } while (n < bound);                         /* bgeu bound,n */
    rf_init_flagword |= 16u;                     /* or 16; store */
}
/* get_rfrx_dcap_bt phy_chip_v7_ana.c:1263 @ phy_chip_v7_ana.o size 54B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[38], g_phyFuns[11] | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: high - call sequence, nibble recombine verified; hooks by table slot */
uint8 get_rfrx_dcap_bt(uint8 reg_addr)
{
    /* v = g_phyFuns[38](100, 0, reg_addr) */
    uint32 v = ((uint32 (*)(uint32, uint32, uint32))g_phyFuns[38])(100, 0, reg_addr & 0xffu);
    /* w = g_phyFuns[11]((v&0xf)-5, 15, 1) */
    uint32 w = ((uint32 (*)(uint32, uint32, uint32))g_phyFuns[11])(((v & 0xfu) - 5u) & 0xffffffffu, 15, 1);
    return (uint8)(((v & 0xfffffff0u) | (w & 0xffu)) & 0xffu);  /* and -16; or; extui */
}
/* get_temp_cal phy_chip_v7_ana.c:1543 @ phy_chip_v7_ana.o size 44B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none - fixed-point + clamp)
 * Fidelity: high - mulsh scale idiom + [-24,24] clamp verified per disasm */
sint16 get_temp_cal(u8 tsen_init, u8 tsen_meas)
{
    int32 d = (int32)(tsen_init & 0xffu) - (int32)(tsen_meas & 0xffu);
    int32 hi = (int32)(((int64)d * (int32)0x92492493ll) >> 32);  /* mulsh */
    int32 v = ((d + hi) >> 2) - (d >> 31);   /* srai round idiom */
    if (v > 24)                              /* blt 24,v -> return 24 */
        return 24;
    return (sint16)(v < -24 ? -24 : v);      /* sext; max -24 */
}
/* i2c_bbpll_init phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 17B [inferred]
 * Calls: i2c_bbpll_init$part$0 (local direct call8) | Data refs: (flag byte +1) | MMIO: (none)
 * Fidelity: high - flag-gated part call verified per disasm */
void i2c_bbpll_init(void)
{
    extern U8 bbpll_init_flag[2];   /* l8ui +1 lane; exact symbol TODO */
    if (bbpll_init_flag[1] != 1)    /* bnei -> return */
        return;
    i2c_bbpll_init$part$0();  /* GCC $ extension; real cold-part symbol */
}
/* i2c_bbpll_init$part$0 phy_chip_v7_ana.c:903 @ phy_chip_v7_ana.o size 72B [dwarf-sig-base-decl]
 * Calls: (indirect) g_phyFuns[42] x4 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: high - 4 ordered I2C writes verified per disasm (arg values as callee a2..a7) */
void i2c_bbpll_init$part$0(void)
{
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (102, 4, 2, 7, 7, 1);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (102, 4, 5, 5, 5, 0);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (102, 4, 5, 7, 6, 1);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (98, 1, 5, 7, 6, 0);
}
/* i2c_bbtop_init phy_chip_v7_ana.c:917 @ phy_chip_v7_ana.o size 84B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40] x4 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: high - 4 ordered I2C writes verified per disasm */
void i2c_bbtop_init(void)
{
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(102, 4, 8, 33);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(102, 4, 9, 132);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 9, 113);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 11, 97);
}
/* i2c_bias_init phy_chip_v7_ana.c:948 @ phy_chip_v7_ana.o size 47B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40] x2 | Data refs: dreg_1p2_set, g_phyFuns (relocs) | MMIO: (none direct)
 * Fidelity: high - two ordered I2C writes verified */
void i2c_bias_init(void)
{
    extern U8 dreg_1p2_set;
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(106, 2, 2, 104);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(106, 2, 0, dreg_1p2_set);
}
/* i2c_bt_filter_set phy_chip_v7_ana.c:954 @ phy_chip_v7_ana.o size 150B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40] x7 | Data refs: (coeff bytes via literal) | MMIO: (none direct)
 * Fidelity: medium - 7 ordered writes verified; coeff-byte source symbol TODO */
void i2c_bt_filter_set(void)
{
    extern U8 bt_filter_src[90];   /* l8ui +88/+89 source; exact symbol TODO */
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 11, 97);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 12, 16);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 15, 234);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 7, (uint8)((bt_filter_src[88] - 2) & 0xffu));
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 8, bt_filter_src[88]);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 5, (uint8)((bt_filter_src[89] - 2) & 0xffu));
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(103, 1, 6, bt_filter_src[89]);
}
/* i2c_rfpll_init phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 140B [inferred]
 * Calls: (indirect) g_phyFuns[40] x6, g_phyFuns[42] x1 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: high - 7 ordered I2C writes verified per disasm */
void i2c_rfpll_init(void)
{
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(99, 0, 1, 243);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (98, 1, 3, 2, 1, 3);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(98, 1, 8, 0);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(98, 1, 10, 176);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(98, 1, 9, 7);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(98, 1, 0, 63);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(98, 1, 4, 191);
}
/* i2c_rftx_init phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 116B [inferred]
 * Calls: (indirect) g_phyFuns[40] x6 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: high - 6 ordered I2C writes verified per disasm */
void i2c_rftx_init(void)
{
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 3, 136);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 4, 6);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 5, 8);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 6, 248);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 7, 93);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 10, 116);
}
/* i2c_write_master phy_chip_v7_ana.c:121 @ phy_chip_v7_ana.o size 114B [dwarf-sig]
 * Calls: esp_dport_access_reg_read (busy-poll) | Data refs: esp_dport_access_reg_read | MMIO: base 0xffd3800 (per-reg <<2 addrs)
 * Fidelity: high - pack law, write loop, per-host busy-poll verified per disasm */
void i2c_write_master(uint8 * block, uint8 * host_id, uint8 * reg_add, uint8 * pData, uint8 num)
{
    uint8 n = (uint8)(num & 0xffu);
    uint8 i;
    if (n == 0)                                  /* beqz -> return */
        return;
    for (i = 0; i < n; i++) {                    /* loop a10=num */
        uint32 addr = ((uint32)(reg_add[i] + 0xffd3800u) << 2);
        uint32 v = ((uint32)host_id[i] << 8) | ((uint32)pData[i] << 16) |
                   (uint32)block[i] | 0x1000000u;
        REG_WRITE(addr, v);                      /* s32i lane */
    }
    {   /* completion poll per host reg; bany-gated re-read */
        uint8 *end = host_id + n;
        uint8 *p = host_id;
        do {
            uint32 addr = ((uint32)(*p + 0xffd3800u) << 2);
            while (REG_READ(addr) & 0x2000000u)   /* bany -> re-read */
                ;
            p++;
        } while (p != end);                      /* bne lane */
    }
}
/* i2c_xtal_init phy_chip_v7_ana.c:337 @ phy_chip_v7_ana.o size 44B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40] x2 | Data refs: g_phyFuns (reloc) | MMIO: (none direct)
 * Fidelity: high - two ordered I2C writes verified; args as callee a2..a5 */
void i2c_xtal_init(void)
{
    /* word 40 = *(g_phyFuns+160). Callee args shown (a2,a3,a4,a5). */
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(104, 3, 0, 99);
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(104, 3, 1, 128);
}
/* phy_bt_ifs_set phy_chip_v7_ana.c:1508 @ phy_chip_v7_ana.o size 57B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff450d0, 0x3ff5103c
 * Fidelity: high - select/merge sequence fully verified per disasm */
void phy_bt_ifs_set(void)
{
    uint32 sel = (REG_READ(0x3ff450d0u) & 0x40000000u) ? 0x1fe000u : 0x1ea000u;
    /* movnez lane: bit30 set -> 0x1fe000 else 0x1ea000 */
    REG_WRITE(0x3ff5103cu, (REG_READ(0x3ff5103cu) & 0xffe007ffu) | sel);
}
/* phy_bt_pll_track phy_chip_v7_ana.c:1514 @ phy_chip_v7_ana.o size 20B [dwarf-sig]
 * Calls: phy_bt_ifs_set | Data refs: phy_bt_ifs_set, phy_bt_pll_track_en (relocs) | MMIO: (none)
 * Fidelity: high - flag store + hook call verified per disasm + relocs */
void phy_bt_pll_track(bool enable)
{
    extern U8 phy_bt_pll_track_en;
    phy_bt_pll_track_en = enable;   /* s8i; memw */
    phy_bt_ifs_set();
}
/* phy_bt_power_track phy_chip_v7_ana.c:1593 @ phy_chip_v7_ana.o size 20B [dwarf-sig]
 * Calls: tsens_read_init | Data refs: phy_bt_power_track_en, tsens_read_init (relocs) | MMIO: (none)
 * Fidelity: high - flag store + hook call verified per disasm + relocs */
void phy_bt_power_track(bool enable)
{
    extern U8 phy_bt_power_track_en;
    phy_bt_power_track_en = enable;   /* s8i; memw */
    tsens_read_init();
}
/* phy_dis_hw_set_freq phy_chip_v7_ana.c:2220 @ phy_chip_v7_ana.o size 88B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff4e0c4, 0x3ff4e168
 * Fidelity: high - poll/program sequence verified per disasm + relocs */
void phy_dis_hw_set_freq(void)
{
    for (;;) {                                     /* 1d0 loop head */
        if ((int32)REG_READ(0x3ff4e168u) < 0) {    /* bltz -> 20e lane */
            if (!(REG_READ(0x3ff4e0c4u) & 0x100u)) /* bnone -> retry */
                continue;
        }
        break;                                     /* -> 1db program lane */
    }
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) | 0x2000000u);
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & ~0x100u);  /* 0xfffffeff */
    ets_delay_us(2);
    (void)REG_READ(0x3ff4e0c4u);
}
/* phy_en_hw_set_freq phy_chip_v7_ana.c:2230 @ phy_chip_v7_ana.o size 75B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: force_hw_set_freq_flag (R_XTENSA_32 @0x388) | MMIO: 0x3ff4e0c4, 0x3ff5c07c
 * Fidelity: high - gate + RMW pair verified per disasm + reloc */
void phy_en_hw_set_freq(void)
{
    extern U8 force_hw_set_freq_flag;
    if (force_hw_set_freq_flag)              /* l8ui gate; bnez -> return */
        return;
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & 0xfdffffffu);
    REG_WRITE(0x3ff5c07cu, (REG_READ(0x3ff5c07cu) & 0xff00ffffu) | 0x9c0000u);
}
/* phy_force_chan phy_chip_v7_ana.c:2412 @ phy_chip_v7_ana.o size 38B [dwarf-sig]
 * Calls: phy_enter_critical, phy_dis_hw_set_freq, freq_write_wifi_chan, phy_exit_critical | Data refs: freq_write_wifi_chan, phy_dis_hw_set_freq, phy_enter_critical, phy_exit_critical (reloc order) | MMIO: (none)
 * Fidelity: high - call order + arg flow verified per disasm + relocs */
void phy_force_chan(uint8 chan_freq)
{
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    phy_dis_hw_set_freq();
    freq_write_wifi_chan((uint8)(chan_freq & 0xffu));  /* extui lane */
    phy_exit_critical_to(crit);                        /* mov a10,a3 lane */
}
/* phy_force_wifi_chan phy_chip_v7_ana.c:2340 @ phy_chip_v7_ana.o size 284B [dwarf-sig]
 * Calls: (indirect) g_phyFuns table + local direct call8s, esp_dport_access_reg_read, phy_enter_critical, bb_rst_en_set, esp_dport_access_reg_read, phy_exit_critical, phy_dis_hw_set_freq | Data refs: phy_force_wifi_chan_en | MMIO: 0x3ff4e0c4, 0x3ff51040, 0x3ff5d008, 0x60033c00
 * Fidelity: medium-low - flag stores, RMW masks, poll-loop skeleton verified; unresolved call targets listed as TODO (no invented names) */
void phy_force_wifi_chan(void)
{
    extern U8 phy_force_wifi_chan_en, phy_sw_set_chan_en;
    uint32 r;
    /* TODO call: indirect opener via g_phyFuns (l32r+callx8 at +0x3); ret -> a7. */
    r = 0;                                         /* placeholder; see rdis */
    phy_force_wifi_chan_en = 1;                    /* s8i lanes + memw */
    phy_sw_set_chan_en = 1;
    /* TODO call: direct local call8 at +0x2e (target in .rela; resolve). */
    REG_WRITE(0x3ff51040u, REG_READ(0x3ff51040u) & ~2u);
    for (;;) {                                     /* settle poll */
        uint32 st = (REG_READ(0x3ff5d008u) >> 29) & 7u;   /* extui 29,3 */
        if (st == 0)
            break;
        if ((REG_READ(0x60033c00u) - r) >= 100u)   /* bgeu 100 lane */
            break;
        /* TODO call: 0x379 lane hook; then flag check -> restore path. */
        break;                                     /* approximate exit; see rdis */
    }
    /* Program path on 0x3ff4e0c4: & ~0x100, (& 0xe7ffffff | 0x10000000 | 0x100),
     * bgez-gated retry with bany check. TODO: exact op order from rdis. */
    /* TODO restore: indirect hook with saved opener return. */
}
/* phy_freq_correct_opt phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 79B [inferred]
 * Calls: (indirect) g_phyFuns[62], esp_dport_access_reg_read x2 | Data refs: g_phyFuns, phy_freq_offset (relocs) | MMIO: 0x3ff4e054, 0x3ff5c400
 * Fidelity: high - hook call + RMW pair verified per disasm + relocs */
void phy_freq_correct_opt(void)
{
    extern sint16 phy_freq_offset;
    ((void (*)(uint32, uint32))g_phyFuns[62])(1, (uint32)(uint16)phy_freq_offset);
    REG_WRITE(0x3ff5c400u, REG_READ(0x3ff5c400u) & 0xfff8ffffu);
    REG_WRITE(0x3ff4e054u, (REG_READ(0x3ff4e054u) & 0xffffff00u) | 200u);
}
/* phy_get_fetx_delay phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 26B [inferred]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff450d0
 * Fidelity: high - body exact per disasm; return type inferred (0/40 fits u8; int used neutrally) */
int phy_get_fetx_delay(void)
{
    uint32 v = REG_READ(0x3ff450d0u);
    v = (v & 0x40000000u) >> 30;   /* and; extui 30,2 */
    return (v != 0) ? 0 : 40;      /* movnez a2,0 */
}
/* phy_hw_set_freq_enable phy_chip_v7_ana.c:2197 @ phy_chip_v7_ana.o size 190B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff4e0c4, 0x3ff4e168, 0x3ff5c07c
 * Fidelity: medium - refcount + poll/program lanes verified; counter symbol TODO */
void phy_hw_set_freq_enable(bool enable)
{
    extern uint32 hw_set_freq_refcount;   /* l32i/s32i lane; exact symbol TODO */
    if (!(enable & 0xffu)) {                       /* bnez -> enable lane */
        if (hw_set_freq_refcount)                  /* bnez -> bump exit */
            goto bump;
        for (;;) {                                 /* dis_hw-style poll */
            if ((int32)REG_READ(0x3ff4e168u) < 0) {
                if (REG_READ(0x3ff4e0c4u) & 0x100u)
                    break;
                continue;
            }
            break;
        }
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) | 0x2000000u);
        ets_delay_us(2);
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & ~0x100u);
bump:
        hw_set_freq_refcount++;                    /* addi; store; ret */
        return;
    }
    if (hw_set_freq_refcount != 1)                 /* bnei -> unbump exit */
        goto unbump;
    {
        extern U8 hw_set_freq_flag;                /* l8ui gate */
        if (hw_set_freq_flag) {
            REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & 0xfdffffffu);
            REG_WRITE(0x3ff5c07cu, (REG_READ(0x3ff5c07cu) & 0xff00ffffu) | 0x9c0000u);
        }
    }
unbump:
    hw_set_freq_refcount--;                        /* addi -1; store; ret */
}
/* phy_i2c_init phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 723B [inferred]
 * Calls: phy_enter_critical, i2c_write_master, i2c_bt_filter_set, phy_exit_critical | Data refs: (staging tables on stack) | MMIO: (none direct)
 * Fidelity: medium-low - phase order (probe reads, table staging, 8x master writes, BT filter, BBPLL part, exit) verified; exact table bytes/args TODO (see rdis) */
void phy_i2c_init(void)
{
    CriticalType crit_level;      /* DWARF l1005 */
    uint8 block[16], host_id[16], reg_add[16], pData[16];  /* DWARF l1007 */
    uint8 bbadc_div, div_dac, bbadc_delay5;   /* DWARF l1008 */
    (void)bbadc_div; (void)div_dac; (void)bbadc_delay5;
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    crit_level = phy_enter_critical_ret();
    /* Probe reads via table word 38: (102,4,10), (102,4,11), (102,4,9). */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(102, 4, 10);
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(102, 4, 11);
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(102, 4, 9);
    /* Stage block/host/reg/data tables on stack (s8i lanes; byte values
     * incl. 99, -13, -88, 119, 3, 0, 1, 107, 98, 4).
     * TODO: expand the ~40 s8i lanes from rdis into the arrays below. */
    /* Eight straight-line master-write bursts over table slices.
     * TODO: exact (ptr, count) per burst from the addi lanes in rdis. */
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_write_master(block, host_id, reg_add, pData, 0);
    i2c_bt_filter_set();
    i2c_bbpll_init$part$0();   /* local .phyiram.23+0x4 call */
    phy_exit_critical_to(crit_level);
}
/* phy_set_wifi_mode_only phy_chip_v7_ana.c:2425 @ phy_chip_v7_ana.o size 14B [dwarf-sig]
 * Calls: (none) | Data refs: phy_freq_wifi_only (R_XTENSA_32 reloc) | MMIO: (none)
 * Fidelity: high - flag store verified per disasm + reloc */
void phy_set_wifi_mode_only(bool wifi_only)
{
    extern U8 phy_freq_wifi_only;
    phy_freq_wifi_only = (U8)wifi_only;   /* s8i a2,a8,0; memw */
}
/* phy_unforce_chan phy_chip_v7_ana.c:2392 @ phy_chip_v7_ana.o size 62B [dwarf-sig]
 * Calls: phy_enter_critical, freq_write_wifi_chan, phy_en_hw_set_freq, phy_exit_critical | Data refs: chip7_sleep_params, freq_write_wifi_chan, phy_en_hw_set_freq (relocs) | MMIO: (none)
 * Fidelity: medium - call order + sleep[81] selection arithmetic verified; default-84 lane kept literal */
void phy_unforce_chan(void)
{
    extern uint8 chip7_sleep_params[];
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    uint8 s = chip7_sleep_params[81];            /* l8ui +81 lane */
    uint8 cf = 84;                               /* movi preset */
    if (s <= 13)                                 /* bltu 13,s -> keep 84 */
        cf = (uint8)((5u * (uint16)(s - 1) + 0x96cu - 96u) & 0xffu);
    freq_write_wifi_chan(cf);
    phy_en_hw_set_freq();
    phy_exit_critical_to(crit);
}
/* phy_unforce_wifi_chan phy_chip_v7_ana.c:2320 @ phy_chip_v7_ana.o size 143B [dwarf-sig]
 * Calls: phy_enter_critical, bb_rst_en_set, esp_dport_access_reg_read, phy_en_hw_set_freq, phy_exit_critical | Data refs: phy_force_wifi_chan_en, force_hw_set_freq_flag, phy_sw_set_chan_en (relocs) | MMIO: 0x3ff4e0c4, 0x3ff4e168, 0x3ff51040
 * Fidelity: high - flag clears, poll lane, RMW pair verified per disasm + relocs */
void phy_unforce_wifi_chan(void)
{
    extern U8 phy_force_wifi_chan_en, force_hw_set_freq_flag, phy_sw_set_chan_en;
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    phy_force_wifi_chan_en = 0;              /* s8i lanes */
    force_hw_set_freq_flag = 0;
    bb_rst_en_set();                         /* local direct call8 */
    if (!phy_sw_set_chan_en) {               /* l8ui gate */
        for (;;) {                           /* 661 poll head */
            if ((int32)REG_READ(0x3ff4e168u) < 0) {
                if (REG_READ(0x3ff4e0c4u) & 0x100u)   /* bnone -> retry */
                    break;
                continue;
            }
            break;
        }
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & 0xe7ffffffu);
    }
    phy_en_hw_set_freq();                    /* local direct call8 */
    REG_WRITE(0x3ff51040u, REG_READ(0x3ff51040u) | 1u);
    phy_exit_critical_to(crit);
}
/* phy_wifi_pll_track phy_chip_v7_ana.c:1503 @ phy_chip_v7_ana.o size 20B [dwarf-sig]
 * Calls: (none) | Data refs: phy_wifi_pll_track_en (R_XTENSA_32 reloc) | MMIO: (none)
 * Fidelity: high - flag store verified per disasm + reloc */
void phy_wifi_pll_track(bool enable)
{
    extern U8 phy_wifi_pll_track_en;
    phy_wifi_pll_track_en = enable;   /* s8i a2,a8,0; memw */
}
/* pll_correct_dcap phy_chip_v7_ana.c:1738 @ phy_chip_v7_ana.o size 238B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[41], esp_dport_access_reg_read, esp_dport_access_reg_read | Data refs: g_phyFuns | MMIO: 0x3ff4e0c0, 0x3ff4e0c4, 0x3ff4e130, 0x3ff4e148
 * Fidelity: medium-low - status trilogy (0/1/-1), program+strobe sequence, cap store verified; hook args + 130-lane source TODO */
sint8 pll_correct_dcap(uint8 freq, u8 * pll_cap_ext, bool wifi_chan_en)
{
    (void)wifi_chan_en;
    /* r = g_phyFuns[41](98, 1, 0, 7, 7, ?); trailing-arg lane approximate. */
    uint32 r = ((uint32 (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[41])(98, 1, 0, 7, 7);
    if (r == 0)
        return 0;
    if (r & 2u) {
        /* Full program lane: 3*freq index program on 0x3ff4e0c4 (mask
         * 0xffffff00), readback combine, 0x3ff4e0c0/0x3ff4e148 staging,
         * strobe set/clear (0x200), s8i cap result to pll_cap_ext[0],
         * then the 0x3ff4e130 write is executed a second time (loop-back
         * to +0x48 before retw). TODO: exact combine arithmetic. */
        uint8 idx = (uint8)(((freq & 0xffu) * 3) & 0xffu);
        REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffffff00u) | idx);
        REG_WRITE(0x3ff4e148u, REG_READ(0x3ff4e0c0u));
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) | 0x200u);
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & ~0x200u);
        *pll_cap_ext = 0;   /* TODO: exact cap value lane (s8i a7) */
        REG_WRITE(0x3ff4e130u, (REG_READ(0x3ff4e130u) & 0xffff00ffu) | 0x0000u);
        return -1;                                 /* a2=255 lane */
    }
    if (!(r & 1u))
        return 0;
    REG_WRITE(0x3ff4e130u, (REG_READ(0x3ff4e130u) & 0xffff00ffu) | 0x0000u);  /* TODO: or-source */
    return 1;
}
/* ram_chip_i2c_readReg phy_chip_v7_ana.c:55 @ phy_chip_v7_ana.o size 228B [dwarf-sig]
 * Calls: phy_enter_critical, phy_dis_hw_set_freq, esp_dport_access_reg_read, phy_en_hw_set_freq, phy_exit_critical | Data refs: (flag bytes via literals) | MMIO: 0x3ff4e044, 0x3ff4e0c4 + per-host (host+0xffd3800)<<2 addrs
 * Fidelity: medium - critical section, mask lane, issue/poll/extract verified; return-lane anomaly noted */
uint8 ram_chip_i2c_readReg(uint8 block, uint8 host_id, uint8 reg_add)
{
    extern U8 i2c_hw_flag, i2c_en_flag;   /* l8ui lanes; exact symbols TODO */
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    block &= 0xffu; host_id &= 0xffu; reg_add &= 0xffu;
    uint8 hw = (host_id < 2) ? 1 : 0;
    if (i2c_hw_flag && hw) {              /* bnez/beqz lanes */
        phy_dis_hw_set_freq();            /* local direct call8 */
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & ~0x100u);
    }
    /* Block mask lane: exactly ~get_i2c_read_mask(block) in both cases
     * (out-of-range: table miss -> a7 stays -1 = ~0 = ~get_i2c_read_mask). */
    uint32 mask = ~get_i2c_read_mask(block);
    REG_WRITE(0x3ff4e044u, (REG_READ(0x3ff4e044u) & 0xfffc00ffu) | 0x3f000u);
    REG_WRITE(0x3ff4e044u, REG_READ(0x3ff4e044u) & mask);
    uint32 addr = ((uint32)(host_id + 0xffd3800u) << 2);
    while (REG_READ(addr) & 0x2000000u)
        ;
    REG_WRITE(addr, ((uint32)reg_add << 8) | REG_READ(addr));  /* issue lane */
    while (REG_READ(addr) & mask)         /* bnez verify-poll */
        ;
    uint8 data = (uint8)((REG_READ(addr) >> 16) & 0xffu);  /* extui 16,8 */
    /* NOTE (verify): data feeds only the gated phy_en_hw_set_freq() call;
     * the function returns via phy_exit_critical_to() (caller-a10 chain),
     * yet DWARF claims uint8 (data-like) return. Transcribed exactly. */
    if (i2c_en_flag == 0 && hw)           /* moveqz lane */
        phy_en_hw_set_freq();
    phy_exit_critical_to(crit);
    return data;                          /* intent per DWARF; see note */
}
/* ram_chip_i2c_writeReg phy_chip_v7_ana.c:99 @ phy_chip_v7_ana.o size 174B [dwarf-sig]
 * Calls: phy_enter_critical, phy_dis_hw_set_freq, esp_dport_access_reg_read, phy_en_hw_set_freq, phy_exit_critical | Data refs: (flag bytes via literals) | MMIO: 0x3ff4e0c4 + per-host (host+0xffd3800)<<2 addrs
 * Fidelity: medium - critical section, hw-gate, write+poll+verify sequence verified; flag symbols TODO */
void ram_chip_i2c_writeReg(uint8 block, uint8 host_id, uint8 reg_add, uint8 pData)
{
    extern U8 i2c_hw_flag, i2c_en_flag;   /* l8ui lanes; exact symbols TODO */
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    block &= 0xffu; host_id &= 0xffu; reg_add &= 0xffu; pData &= 0xffu;
    uint8 hw = (host_id < 2) ? 1 : 0;            /* bltui lane */
    if (i2c_hw_flag && hw) {
        phy_dis_hw_set_freq();                   /* local direct call8 */
        REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & ~0x100u);
    }
    uint32 addr = ((uint32)(host_id + 0xffd3800u) << 2);
    while (REG_READ(addr) & 0x2000000u)           /* bany busy-poll */
        ;
    REG_WRITE(addr, (uint32)host_id | 0x1000000u |
                    ((uint32)reg_add << 8) | ((uint32)pData << 16));
    while (REG_READ(addr) & 0xffd3800u)           /* bnez verify-poll */
        ;
    if (i2c_en_flag == 0 && hw)                  /* moveqz lane */
        phy_en_hw_set_freq();                    /* local direct call8 */
    phy_exit_critical_to(crit);
}
/* ram_pbus_debugmode phy_chip_v7_ana.c:200 @ phy_chip_v7_ana.o size 39B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[43], esp_dport_access_reg_read, phy_printf | Data refs: esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff46094
 * Fidelity: high - sequence + bit0 early-exit verified */
void ram_pbus_debugmode(void)
{
    ((void (*)(uint32))g_phyFuns[43])(1);      /* table+172 lane */
    uint32 v = REG_READ(0x3ff46094u);
    if (v & 1u)                                /* bbsi a10,0 -> return */
        return;
    phy_printf();                              /* diagnostic; fmt via rodata literal */
}
/* ram_pbus_force_mode phy_chip_v7_ana.c:180 @ phy_chip_v7_ana.o size 202B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff00024, 0x3ff46094, 0x3ff4609c, 0x3ff5c02c
 * Fidelity: high - enable/disable lanes, poll loop, cross-reg field copy verified per disasm */
void ram_pbus_force_mode(bool pbus_force_en)
{
    if (pbus_force_en & 0xffu) {                 /* beqz -> disable lane */
        REG_WRITE(0x3ff4609cu, REG_READ(0x3ff4609cu) & 0xf7ffffffu);
        REG_WRITE(0x3ff46094u, REG_READ(0x3ff46094u) | 1u);
        return;
    }
    REG_WRITE(0x3ff46094u, REG_READ(0x3ff46094u) & ~2u);
    REG_WRITE(0x3ff4609cu, REG_READ(0x3ff4609cu) & 0xf7ffffffu);
    while (REG_READ(0x3ff00024u) & 2u)            /* bnone -> exit poll */
        ets_delay_us(1);
    /* Cross-reg field copy 4609c -> 5c02c with 0x32000000 set. */
    REG_WRITE(0x3ff5c02cu, (REG_READ(0x3ff4609cu) & 0xf7ffffffu) | 0x32000000u);
    REG_WRITE(0x3ff5c02cu, REG_READ(0x3ff5c02cu) | 0x800000u);
    ets_delay_us(2);
    REG_WRITE(0x3ff5c02cu, REG_READ(0x3ff5c02cu) & 0xff7fffff);
}
/* ram_pbus_force_test phy_chip_v7_ana.c:237 @ phy_chip_v7_ana.o size 97B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff46094, 0x3ff460a0
 * Fidelity: high - field pack, set/poll/clear sequence verified per disasm */
void ram_pbus_force_test(u8 pbus_no, u8 bus_en, u16 config_data)
{
    uint32 f = (((uint32)(config_data & 0xffffu) << 6) |
                ((uint32)(pbus_no & 0xffu) << 2) |
                ((uint32)(bus_en & 0xffu) << 15)) & 0x1fffcu;
    REG_WRITE(0x3ff46094u, (REG_READ(0x3ff46094u) & 0xfffe0001u) | f | 2u);
    while ((int32)REG_READ(0x3ff460a0u) >= 0)   /* bltz poll */
        ;
    REG_WRITE(0x3ff46094u, REG_READ(0x3ff46094u) & ~3u);  /* movi -3 lane */
}
/* ram_pbus_xpd_tx_on phy_chip_v7_ana.c:323 @ phy_chip_v7_ana.o size 160B [dwarf-sig]
 * Calls: ram_pbus_force_test x5, (indirect) g_phyFuns[47], g_phyFuns[55] | Data refs: g_phyFuns, ram_pbus_force_test | MMIO: (none direct; all via callees)
 * Fidelity: medium - call sequence + arg values verified; w46=ram_pbus_force_test per gphyfuns_map.json; w47/w55 symbolic */
void ram_pbus_xpd_tx_on(U16 pa_gain, U16 bbgain)
{
    sint16 dc_comp[4];   /* DWARF l325: sint16 dc_comp[]; 4 halfwords spilled to stack */
    (void)dc_comp;
    /* pbus TX power-up sequence. Accessors: w46 = *(g_phyFuns+184),
     * w47 = *(g_phyFuns+188), w55 = *(g_phyFuns+220). Args are caller
     * a10/a11/a12 -> callee a2/a3/a4 (windowed call8). */
    PBUS_FORCE_TEST(0, 1, 1);
    PBUS_FORCE_TEST(1, 1, 124);
    ((void (*)(void *))g_phyFuns[55])(dc_comp);   /* stack image arg */
    PBUS_FORCE_TEST(1, 2, (uint32)(pa_gain & 0xffffu));
    if (!((bbgain >> 8) & 1)) {                  /* bbci a2,8 */
        uint32 r = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(1, 1);
        ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(1, 1, (r | 2u) & 0xffffu);
    }
    PBUS_FORCE_TEST(4, 1, 127);
    PBUS_FORCE_TEST(5, 1, (uint32)(bbgain & 0xffffu)); /* final bbgain stage */
}
/* ram_restart_cal phy_chip_v7_ana.c:386 @ phy_chip_v7_ana.o size 94B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[42] x4 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium - 4-call sequence + all arg values verified per disasm; callee identity symbolic (no reloc name; slot +168 = word 42) */
void ram_restart_cal(void)
{
    /* BBPLL/I2C restart pattern: 4 ordered writes through g_phyFuns word 42
     * (*(g_phyFuns+168)). Args shown as callee (a2..a7) = caller (a10..a15). */
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (98, 1, 0, 6, 6, 1);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (98, 1, 0, 5, 5, 0);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (98, 1, 0, 5, 5, 1);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (98, 1, 0, 6, 6, 0);
}
/* ram_rfpll_reset phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 5B [inferred]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - empty body (entry + retw) verified per disasm */
void ram_rfpll_reset(void)
{
    return;
}
/* ram_rfpll_set_freq phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 153B [inferred]
 * Calls: __floatunsidf, __divdf3, __truncdfsf2, __divsf3 | Data refs: (crystal MHz table via literal) | MMIO: (none)
 * Fidelity: medium - divider law + 3-byte SDM split verified (consts 40960.0/3.0/1024.0/32.0/256.0); invalid-crystal lane approximate */
void ram_rfpll_set_freq(uint32 freq, uint8 crystal_select, sint16 freq_offset, uint8 * x_reg)
{
    float fvco, div_sdm, x2_f, crystal_val;   /* DWARF l424 */
    uint8 status; (void)status;               /* DWARF l425 */
    extern const float crystal_mhz_table[4];  /* lsi source; exact symbol TODO */
    /* fixed = ((freq<<10) + offset) << 2; fvco = (double)fixed / 3.0 */
    uint32 fx = ((uint32)(((freq & 0xffffffffu) << 10) + (uint32)(int32)(int16)freq_offset) << 2);
    double d = (double)fx / 3.0;              /* __floatunsidf + __divdf3 */
    float f = (float)d;                       /* __truncdfsf2 */
    uint8 ci = (uint8)((crystal_select - 1) & 0xffu);
    if (ci < 4)
        crystal_val = crystal_mhz_table[ci];  /* lsi lane */
    else
        crystal_val = 1.0f;                   /* TODO: stale-f2 lane; VERIFY */
    /* v = f / (xtal*1024) - 32 (__divsf3); 3-byte SDM split. */
    float v = f / (crystal_val * 1024.0f) - 32.0f;
    (void)fvco; (void)div_sdm; (void)x2_f;
    uint8 b0 = (uint8)v;                      /* utrunc.s */
    float r1 = v - (float)b0;
    uint8 b1 = (uint8)(r1 * 256.0f);
    float r2 = r1 - (float)b1;
    uint8 b2 = (uint8)(r2 * 256.0f);
    x_reg[0] = b0;                            /* s8i lanes */
    x_reg[1] = b1;
    x_reg[2] = b2;
}
/* ram_wait_rfpll_cal_end phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 64B [inferred]
 * Calls: ets_delay_us, (indirect) g_phyFuns[41], phy_printf | Data refs: ets_delay_us, g_phyFuns, phy_printf | MMIO: (none direct)
 * Fidelity: medium - poll/timeout skeleton verified; hook args approximate (a15 lane stale) */
void ram_wait_rfpll_cal_end(void)
{
    int tmo = 100;                               /* movi a2,100 */
    for (;;) {
        ets_delay_us(20);
        /* ret = g_phyFuns[41](98, 1, 7, 7, 7) — a15 lane unverified. */
        uint32 done = ((uint32 (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[41])(98, 1, 7, 7, 7);
        int next = (tmo - 1) & 0xff;             /* addi -1; extui */
        if (done != 0)                           /* bnez -> calibrated */
            return;
        if (tmo == 1) {                          /* bnei 1 -> loop */
            phy_printf();                        /* timeout diagnostic */
            return;
        }
        tmo = next;
    }
}
/* rf_init phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 134B [inferred]
 * Calls: i2c_bias_init, reg_init_begin, rfpll_1p2_opt, phy_i2c_init, set_chan_freq_hw_init | Data refs: i2c_bias_init, phy_i2c_init, reg_init_begin, rfpll_1p2_opt | MMIO: (none direct; via table hooks)
 * Fidelity: medium - init order, flag gates, hook sequence verified; hook args (none set up) as-is */
void rf_init(void)
{
    extern U8 rf_init_flag_a, rf_init_flag_b;   /* l8ui gates; exact symbols TODO */
    i2c_bias_init();
    reg_init_begin();   /* a10=0 set up but unused per DWARF void(void) */
    rfpll_1p2_opt();
    phy_i2c_init();
    if (!rf_init_flag_a)                         /* beqz lane */
        goto program;
    if (rf_init_flag_b)                          /* bnez -> skip program */
        goto done;
program:
    ((void (*)(void))g_phyFuns[48])();           /* +192 lane */
    {
        uint16 img[4]; (void)img;                /* stack image for +220 */
        ((void (*)(void *))g_phyFuns[55])(img);  /* +220 lane */
    }
    ((void (*)(void))g_phyFuns[53])();           /* +212 lane */
    ((void (*)(void))g_phyFuns[51])();           /* +204 lane */
    ((void (*)(void))g_phyFuns[49])();           /* +196 lane */
done:
    set_chan_freq_hw_init(2, 4);                 /* a10=2,a11=4 lane */
}
/* rfpll_1p2_opt phy_chip_v7_ana.c:? @ phy_chip_v7_ana.o size 111B [inferred]
 * Calls: (indirect) g_phyFuns[38], g_phyFuns[40] | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium - verify loop + conditional dreg write verified; table symbol TODO */
void rfpll_1p2_opt(void)
{
    extern U8 rfpll_expect_tbl[4];   /* l8ui source; exact symbol TODO */
    extern U8 dreg_opt_flag;         /* s8i 42 target; exact symbol TODO */
    uint8 stage[4];
    for (int i = 0; i < 4; i++)
        stage[i] = rfpll_expect_tbl[i];
    uint8 mism = 0;
    for (int i = 0; i < 4; i++) {                /* bnei 4 lane */
        /* r = g_phyFuns[38](98, 1, i); trailing args stale. */
        uint32 r = ((uint32 (*)(uint32, uint32, uint32))g_phyFuns[38])(98, 1, (uint32)i);
        if ((uint8)r != stage[i])                /* beq -> match */
            mism = (uint8)((mism + 1) & 0xffu);
    }
    if (mism == 0)                               /* beqz -> return */
        return;
    dreg_opt_flag = 42;                          /* s8i lane */
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(106, 2, 0, 42);
}
/* set_chan_freq_hw_init phy_chip_v7_ana.c:2051 @ phy_chip_v7_ana.o size 172B [dwarf-sig]
 * Calls: get_rf_freq_init$part$2, bt_get_i2c_data, bt_i2c_write_set, write_wifi_chan_data, esp_dport_access_reg_read, i2cmst_reg_init | Data refs: bt_get_i2c_data, bt_i2c_write_set, i2cmst_reg_init | MMIO: 0x60033d38
 * Fidelity: medium-low - init gates, table-stage loops, final program verified; exact table/arg mapping TODO */
void set_chan_freq_hw_init(S8 tx_freq_offset, S8 rx_freq_offset)
{
    extern uint32 hw_init_flagword;   /* bit4/bit0x2000 gates; exact symbol TODO */
    U8 tab_a[16], tab_b[16], tab_c[16], tab_d[16], tab_e[16];  /* stack tables */
    (void)tx_freq_offset; (void)rx_freq_offset;
    if (hw_init_flagword & 0x10) {    /* bbsi 4 -> tiny hook + return */
        /* TODO: indirect hook at +0xc (table slot resolvable via reloc). */
        return;
    }
    if (!(hw_init_flagword & 0x2000)) /* bnone -> d4 tail */
        goto tail;
    /* Stage tables (11- and 12-entry copy loops), then program: */
    bt_get_i2c_data(tab_a, tab_b, tab_c, tab_d, tab_e, tab_a, tab_b, 11, tab_c);
    bt_i2c_write_set(tab_a, tab_b, tab_c, tab_d, tab_e, tab_a, tab_b, 11, tab_c);
    REG_WRITE(0x60033d38u, (REG_READ(0x60033d38u) & 0xffffu) | 0xc800000u);
tail:
    i2cmst_reg_init();                /* unresolved decl; presumed void(void) */
}
/* set_chan_freq_sw_start phy_chip_v7_ana.c:2249 @ phy_chip_v7_ana.o size 443B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_dis_hw_set_freq, correct_rfpll_offset, write_wifi_chan_data, ets_delay_us, pll_correct_dcap, phy_en_hw_set_freq | Data refs: correct_rfpll_offset, phy_dis_hw_set_freq, phy_en_hw_set_freq, pll_correct_dcap, write_wifi_chan_data | MMIO: 0x3ff4e0c4
 * Fidelity: medium-low - phase order (snapshot, RMW, 12-try poll, fixup, status gate, restore), call sequence verified; nibble arithmetic approximate */
void set_chan_freq_sw_start(U8 chan_freq, sint16 freq_offset, uint8 crystal_select)
{
    uint8 ch = (uint8)(chan_freq & 0xffu);
    sint16 off = freq_offset;                    /* sext 15 */
    uint8 xtal = (uint8)(crystal_select & 0xffu);
    (void)off; (void)xtal;
    extern U8 sw_start_flag;   /* s8i lane; exact symbol TODO */
    sw_start_flag = 1;
    /* Snapshot nibbles 16-19 and 20-23 of 0x3ff4e0c4 to stack. */
    uint8 nib_lo = (uint8)((REG_READ(0x3ff4e0c4u) >> 16) & 0xfu);
    uint8 nib_hi = (uint8)((REG_READ(0x3ff4e0c4u) >> 20) & 0xfu);
    (void)nib_lo; (void)nib_hi;
    phy_dis_hw_set_freq();
    /* RMW series (masks 0xfff0ffff, 0xff0fffff, 0xffffff00|ch, strobe). */
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & 0xfff0ffffu);
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & 0xff0fffff);
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffffff00u) | ch);
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) | 0x100u);
    ets_delay_us(2);
    /* Poll loop, up to 12 tries (a6=12 countdown). */
    for (int t = 12; t > 0; t--) {               /* bnez countdown lane */
        uint32 st = REG_READ(0x3ff4e0c4u);
        if ((int32)st >= 0)                      /* bgez exit */
            break;
        REG_WRITE(0x3ff4e0c4u, st & ~0x100u);
        ets_delay_us(40);
        /* status-byte checks (sext/bnei lanes) may exit early. */
    }
    correct_rfpll_offset(off, xtal);
    write_wifi_chan_data(ch);
    {
        uint8 cap_buf[4]; (void)cap_buf;
        pll_correct_dcap(ch, cap_buf, 1);   /* a10=ch?,a11=sp,a12=1 lanes; TODO exact */
    }
    /* Restore nibbles, clear flag, enable HW. */
    sw_start_flag = 0;
    phy_en_hw_set_freq();
}
/* set_channel_rfpll_freq phy_chip_v7_ana.c:740 @ phy_chip_v7_ana.o size 145B [dwarf-sig]
 * Calls: phy_printf, esp_dport_access_reg_read, set_chan_freq_sw_start, write_wifi_chan_data | Data refs: chip7_sleep_params, phy_printf, set_chan_freq_sw_start, write_wifi_chan_data | MMIO: (object-relative literals only)
 * Fidelity: medium - bypass-vs-PLL branch, call order, uint16 return verified; exact PLL-path reg bit ops TODO */
uint16 set_channel_rfpll_freq(int8 channel, uint8 crystal_select, sint16 freq_offset)
{
    uint16 freq;          /* DWARF l742 */
    uint16 chan_freq;     /* DWARF l742 */
    extern uint8 chip7_sleep_params[];
    (void)freq_offset;
    if (!(chip7_sleep_params[0] & 0x10)) {       /* bbsi a5,4 falls through -> bypass */
        /* Test bypass: indirect hook via g_phyFuns word 61 (l32i a2,a2,244),
         * then return sign-extended channel. */
        ((void (*)(int8, uint8))g_phyFuns[61])((int8)channel, crystal_select);
        return (uint16)(int16)(int8)channel;     /* sext a10,a2,7 */
    }
    /* PLL path (DWARF l742+): range-check channel/crystal, phy_printf on bad
     * combo, DPORT RMW sequence, set_chan_freq_sw_start handshake, then
     * write_wifi_chan_data(chan_freq). TODO: exact reg bit ops from rdis. */
    chan_freq = 0;                               /* TODO: freq computation */
    freq = chan_freq;
    set_chan_freq_sw_start((U8)chan_freq, freq_offset, crystal_select);
    write_wifi_chan_data((uint8)chan_freq);
    return freq;
}
/* tsens_code_read phy_chip_v7_ana.c:1530 @ phy_chip_v7_ana.o size 114B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x6 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48844, 0x3ff4884c
 * Fidelity: medium - RMW chain + trigger/read ordering exact; return-width caveat (see note) */
uint8 tsens_code_read(void)
{
    /* NOTE (verify): DWARF says uint8 return but the low-byte extraction
     * (extui a2,22,8 of 0x3ff48844) is dead in disasm; caller a10 carries the
     * final written word. Transcribed exactly; consumer btpwr_tsens_track
     * uses the wide value then & 0xffff. */
    REG_WRITE(0x3ff4884cu, REG_READ(0x3ff4884cu) | 0x4000000u);   /* trigger */
    uint32 meas = REG_READ(0x3ff48844u);
    uint8 code = (uint8)((meas >> 22) & 0xffu);   /* extracted; unused below */
    (void)code;
    REG_WRITE(0x3ff4884cu, REG_READ(0x3ff4884cu) & 0xfbffffffu);
    REG_WRITE(0x3ff4884cu, REG_READ(0x3ff4884cu) & 0xfeffffffu);
    uint32 last = REG_READ(0x3ff4884cu) | 0x1000000u;  /* final or lane */
    REG_WRITE(0x3ff4884cu, last);
    return (uint8)last;   /* caller-a10 value; DWARF uint8 => low byte */
}
/* tsens_read_init phy_chip_v7_ana.c:1521 @ phy_chip_v7_ana.o size 93B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x4 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4884c
 * Fidelity: high - linear RMW chain fully verified per disasm */
void tsens_read_init(void)
{
    REG_WRITE(0x3ff4884cu, (REG_READ(0x3ff4884cu) & 0xff00ffffu) | 0x20000u);
    REG_WRITE(0x3ff4884cu, REG_READ(0x3ff4884cu) | 0x2000000u);
    REG_WRITE(0x3ff4884cu, REG_READ(0x3ff4884cu) & 0xfeffffffu);
    REG_WRITE(0x3ff4884cu, REG_READ(0x3ff4884cu) | 0x1000000u);
}
/* wifi_track_pll_cap phy_chip_v7_ana.c:1705 @ phy_chip_v7_ana.o size 142B [dwarf-sig]
 * Calls: phy_enter_critical, esp_dport_access_reg_read, phy_dis_hw_set_freq, pll_correct_dcap, phy_en_hw_set_freq, phy_exit_critical | Data refs: (flag bytes via literals) | MMIO: 0x3ff5d008
 * Fidelity: medium - gate chain, channel-index compute, correct/store sequence verified; flag symbols TODO */
void wifi_track_pll_cap(void)
{
    extern U8 track_arm_flag, track_en_flag2, track_en_flag3;  /* exact symbols TODO */
    extern uint8 sleep_byte81;       /* sext lane */
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    U8 cap_staged = 0;               /* s8i sp+0 lane */
    if (!track_arm_flag)
        goto out;
    if (REG_READ(0x3ff5d008u) & 0x20000000u)   /* bbsi 29 */
        goto out;
    if (!track_en_flag2)             /* bnez lane */
        goto out;
    {
        uint8 idx = 84;                        /* movi preset */
        int8 ch = (int8)sleep_byte81;          /* sext lane */
        if (ch <= 13)                          /* blt 13,ch -> keep 84 */
            idx = (uint8)(((ch * 5) + 7) & 0xffu);  /* addx4; addi 7 */
        phy_dis_hw_set_freq();                 /* local direct call8 */
        /* r = pll_correct_dcap(idx, &cap_staged, 1); a11=sp,a12=1 lane */
        uint8 r = (uint8)pll_correct_dcap(idx, &cap_staged, 1);
        if (r && cap_staged)                   /* dual beqz gates */
            ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(98, 1, 1, cap_staged);
    }
    if (track_en_flag3)                        /* bnez -> out */
        goto out;
    phy_en_hw_set_freq();                      /* local direct call8 */
out:
    phy_exit_critical_to(crit);                /* mov a10,a2 lane */
}
/* wr_rf_freq_mem phy_chip_v7_ana.c:1216 @ phy_chip_v7_ana.o size 111B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e0c4, 0x3ff4e148
 * Fidelity: medium - loop bound (3 words), MMIO sequence + strobe bit verified per disasm */
void wr_rf_freq_mem(uint8 chan_freq, uint32 * mem_data)
{
    uint8 k; (void)k;
    uint8 addr; (void)addr;
    uint32 data;
    /* DWARF l1218: k, addr; l1219: data. Stack slot holds end pointer. */
    uint32 *end = mem_data + 3;                  /* addi.n a5,a3,12; spill to stack */
    uint8 idx = (uint8)((chan_freq * 3) & 0xff); /* extui; addx2 (x3); extui */
    do {
        data = *mem_data;                        /* l32i.n a5,a3,0 */
        uint32 v = REG_READ(0x3ff4e0c4);         /* esp_dport_access_reg_read */
        REG_WRITE(0x3ff4e0c4, (v & 0xffffff00u) | idx);
        REG_WRITE(0x3ff4e148, data);             /* data word to RF freq mem port */
        v = REG_READ(0x3ff4e0c4);
        REG_WRITE(0x3ff4e0c4, v | 0x200u);       /* strobe bit 9 */
        v = REG_READ(0x3ff4e0c4);
        REG_WRITE(0x3ff4e0c4, v & ~0x200u);      /* 0xfffffdff; release strobe */
        idx++;                                   /* extui keeps it 8-bit */
        mem_data++;
    } while (mem_data != end);                   /* bne end,a3 -> loop head */
}
/* write_freq_mem_all phy_chip_v7_ana.c:1231 @ phy_chip_v7_ana.o size 154B [dwarf-sig]
 * Calls: phy_byte_to_word, wr_rf_freq_mem | Data refs: chip7_sleep_params, phy_byte_to_word, phy_freq_wifi_only, wr_rf_freq_mem | MMIO: (none direct)
 * Fidelity: medium-low - gate, word-pack loop, per-freq wr_rf_freq_mem sweep verified; index arithmetic approximate */
void write_freq_mem_all(uint8 * rf_cal_data)
{
    uint32 mem_data[8];      /* DWARF: u32 mem_data[] (size approximate) */
    uint32 start; (void)start;
    uint8 i; (void)i;
    uint8 set_freq_num;      /* loop bound from flag lane */
    uint8 chan_freq;
    uint8 k; (void)k;
    uint16 freq; (void)freq;
    extern uint32 rf_mode_word;   /* (&24)==16 gate; exact symbol TODO */
    if ((rf_mode_word & 24u) != 16u) {   /* beqi -> else */
        rf_mode_word |= 8u;               /* or 8; store; return */
        return;
    }
    extern U8 freq_mode_flag;   /* movnez source; exact symbol TODO */
    extern uint32 phy_byte_to_word_ret(void);  /* usage-typed: decl says void, a10 used */
    (void)rf_cal_data;
    set_freq_num = freq_mode_flag ? 14 : 85;   /* movnez lane; stored sp+20 */
    for (chan_freq = 0; chan_freq < set_freq_num; chan_freq++) {
        for (i = 0; i < 8; i++)              /* bne-bounded pack lane */
            mem_data[i] = phy_byte_to_word_ret();  /* s32i lane */
        wr_rf_freq_mem(chan_freq, mem_data);
    }
}
/* write_wifi_chan_data phy_chip_v7_ana.c:2014 @ phy_chip_v7_ana.o size 216B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, get_lna_vga_dcap_val, bt_i2c_set_wifi_data | Data refs: bt_i2c_set_wifi_data, bt_wifi_chan_data, esp_dport_access_reg_read, freq_i2c_addr, get_lna_vga_dcap_val | MMIO: 0x3ff4e0c0, 0x3ff4e0c4
 * Fidelity: medium - loop bounds (3, 11), call order, MMIO addrs, shift/mask/threshold constants verified per disasm; rodata table base + out-buffer literal symbolic */
void write_wifi_chan_data(uint8 chan_freq)
{
    uint8 i; (void)i;
    uint8 mem_addr; (void)mem_addr;
    uint8 data; (void)data;
    uint8 shift; (void)shift;
    uint8 addr; (void)addr;
    uint8 pll_cap;
    uint32 mem_data[3];      /* DWARF l2017: u32 mem_data[] — 3 saved readbacks */
    sint16 rfrx_cap[6];      /* DWARF l2018: sint16 rfrx_cap[] — cal outputs */
    /* Phase 1: program 3 chan indices, save readbacks. */
    uint8 idx = (uint8)((chan_freq * 3) & 0xff);  /* extui; addx2; extui */
    uint8 end = (uint8)((idx + 3) & 0xff);
    uint32 *sp = mem_data;
    do {
        uint32 v = REG_READ(0x3ff4e0c4);
        REG_WRITE(0x3ff4e0c4, (v & 0xffffff00u) | idx);
        v = REG_READ(0x3ff4e0c0);
        idx = (uint8)((idx + 1) & 0xff);
        *sp++ = v;                                /* s32i.n a10,a7,0; a7+=4 */
    } while (idx != end);                         /* bne a2,a4 */
    /* Phase 2: LNA/VGA dcap lookup, then 11-byte bit-pack of the i2c image.
     * NOTE (windowed ABI): mem_data[0] is loaded into caller a2 BEFORE the
     * call and survives it (caller a0..a7 are callee-invisible); the 11-loop
     * consumes it directly with no reload — verified in disasm. */
    pll_cap = (uint8)(mem_data[0] & 0xff);
    get_lna_vga_dcap_val(pll_cap, rfrx_cap);      /* out buf = sp+12 as callee a3 */
    {
        uint8 *tbl = freq_i2c_table();            /* rodata base via literal; cf. freq_i2c_addr */
        uint8 *out = i2c_image_buf();             /* out buffer via literal */
        uint32 w0 = mem_data[0], w1 = mem_data[1], w2 = mem_data[2];
        for (i = 0; i < 11; i++) {                /* loop a11=11 */
            uint8 t = tbl[i];                     /* l8ui a8,a10,0 */
            if (t <= 15)
                continue;                         /* bgeu -> c1: slot untouched */
            else if (t <= 19)
                out[i] = (uint8)((w0 >> ((t * 8) & 31)) & 0xff);  /* ssr/srl, extui */
            else if (t <= 23)
                out[i] = (uint8)((w1 >> ((t * 8) & 31)) & 0xff);
            else
                out[i] = (uint8)((w2 >> ((t * 8) & 31)) & 0xff);
        }
        /* Byte fixups at offsets 9..10, then stage to coexistence regs. */
        out[9] = (uint8)(((out[9] & 0xf0u) | (uint8)(rfrx_cap[0] & 0xff)) & 0xff);
        (void)mem_addr; (void)data; (void)shift; (void)addr;
        bt_i2c_set_wifi_data((U8 *)out, 11);      /* a10=out, a11=11 */
    }
}
/* Undefined refs (29): __divdf3, __divsf3, __floatunsidf, __truncdfsf2, bb_bss_cbw40, bt_tx_gain_cal_set, chan14_mic_cfg, chan14_mic_en, chip7_phy_init_ctrl, chip7_sleep_params, chip_sleep_prot_dis, chip_sleep_prot_en, chip_v7_set_chan_misc, disable_wifi_agc, enable_wifi_agc, esp_dport_access_reg_read, ets_delay_us, force_hw_set_freq_flag, g_phyFuns, i2cmst_reg_init, phy_byte_to_word, phy_dis_pwdet_one, phy_enter_critical, phy_exit_critical, phy_init_flag, phy_printf, phy_wifi_bb_reset, re_entry, reg_init_begin */