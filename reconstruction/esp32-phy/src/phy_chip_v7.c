/* Reconstruction of phy_chip_v7.o (libphy.a)
 * CU: phy_chip_v7.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/phy
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 216 | funcdb functions: 152
 * Disasm: re/esp32-phy/disasm/libphy/phy_chip_v7.rdis
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
extern unsigned g_phyFuns[];  /* indirect-call table referenced via offsets */

/* agc_reg_init phy_chip_v7.c:? @ phy_chip_v7.o size 423B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x14 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c018, 0x3ff5c01c, 0x3ff5c024, 0x3ff5c028, 0x3ff5c038, 0x3ff5c044, 0x3ff5c07c, 0x3ff5c088, 0x3ff5c094, 0x3ff5c0a4, 0x3ff5c0c4, 0x3ff5c0f8, 0x3ff5c104, 0x3ff5c0f8, 0x3ff5c11c, 0x3ff5c120, 0x3ff5cc04, 0x3ff5cc08, 0x3ff5cc0c, 0x3ff5cc48, 0x3ff5ccdc, 0x3ff5cce4, 0x3ff5cd04, 0x3ff5cd08, 0x3ff5ccd8, 0x3ff5c400
 * Fidelity: high - 20-lane AGC program verified per disasm (one mask VERIFY-flagged) */
void agc_reg_init(void)
{
    REG_WRITE(0x3ff5c004u, REG_READ(0x3ff5c004u) & 0xfffeffffu);
    REG_WRITE(0x3ff5c0a4u, (REG_READ(0x3ff5c0a4u) & 0xffffc07fu) | 0x1e00u);
    REG_WRITE(0x3ff5c0a4u, (REG_READ(0x3ff5c0a4u) & ~0x80u) | 60u);
    REG_WRITE(0x3ff5cc48u, 0x170433afu);
    REG_WRITE(0x3ff5cce4u, REG_READ(0x3ff5cce4u) & 0xffbfffffu);
    REG_WRITE(0x3ff5c400u, (REG_READ(0x3ff5c400u) & 0xffff9f00u) | 0x60a5u);
    REG_WRITE(0x3ff5cd04u, 0x51510556u);
    REG_WRITE(0x3ff5cd08u, 0x51510556u);
    REG_WRITE(0x3ff5cc0cu, 0x1241fcu);
    REG_WRITE(0x3ff5cc08u, 0x90b4d20u);
    REG_WRITE(0x3ff5ccdc, 0x195c83cu);
    REG_WRITE(0x3ff5c044u, (REG_READ(0x3ff5c044u) & 0xfe00ffffu) | 0x1fb0000u);
    REG_WRITE(0x3ff5c024u, (REG_READ(0x3ff5c024u) & 0xfffc01ffu) | 0x36800u);
    REG_WRITE(0x3ff5c094u, 0x1b8dd03u);
    REG_WRITE(0x3ff5cc04u, (REG_READ(0x3ff5cc04u) & 0xfffffe03u) | 44u);
    REG_WRITE(0x3ff5ccd8u, 0x186u);
    REG_WRITE(0x3ff5c038u, (REG_READ(0x3ff5c0f8u) & 0xfffc01ffu) | 0x37400u);
    REG_WRITE(0x3ff5c028u, REG_READ(0x3ff5c028u) & 0xf7ffffffu);
    /* VERIFY mask: a2 lane has no literal setup in linear flow; 0xfffffff8
     * assumed from the |5 pattern. */
    REG_WRITE(0x3ff5c088u, (REG_READ(0x3ff5c088u) & 0xfffffff8u) | 5u);
    REG_WRITE(0x3ff5c104u, REG_READ(0x3ff5c104u) & 0xffff7fffu);
    REG_WRITE(0x3ff5c07cu, (REG_READ(0x3ff5c07cu) & 0xff00ffffu) | 0x9c0000u);
}
/* analog_gain_init phy_chip_v7.c:? @ phy_chip_v7.o size 191B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[48,46,55,49] | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium - hook order + stage loop verified; stack-image contents TODO */
void analog_gain_init(void)
{
    uint16 img[4]; (void)img;   /* l16ui/s16i staging lanes */
    ((void (*)(void *))g_phyFuns[48])(img);            /* +192 lane */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(4, 1, 0);
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(5, 1, 0);
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(0, 1, 0x184);
    for (int stage = 1; stage <= 2; stage++) {         /* a3=1..2 lane */
        /* w46(1,1,0x18b) unless arg already 1 (beq skip lane). */
        ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(1, 1, 0x18b);
        ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(1, 2, 0);
        ((void (*)(void *))g_phyFuns[55])(img);        /* +220 lane */
    }
    ((void (*)(void))g_phyFuns[49])();                 /* +196 lane */
}
/* ant_btrx_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 155B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4510c, 0x3ff45110, 0x3ff5c11c
 * Fidelity: high - 5-lane BT-RX antenna program verified per disasm */
void ant_btrx_cfg(bool auto_en, uint8 ant0, uint8 ant1)
{
    uint8 a0 = (uint8)(ant0 & 0xfu), a1 = (uint8)(ant1 & 0xfu);
    REG_WRITE(0x3ff5c11cu, (REG_READ(0x3ff5c11cu) & ~9u) | (((uint32)(auto_en & 1u)) << 3));
    REG_WRITE(0x3ff4510cu, (REG_READ(0x3ff4510cu) & 0xfffff0ffu) | ((uint32)a0 << 8));
    REG_WRITE(0x3ff4510cu, (REG_READ(0x3ff4510cu) & 0xfff0ffffu) | ((uint32)a1 << 16));
    REG_WRITE(0x3ff4510cu, (REG_READ(0x3ff4510cu) & 0xf0ffffffu) | ((uint32)a1 << 24));
    REG_WRITE(0x3ff45110u, (REG_READ(0x3ff45110u) & ~0xfu) | a1);
}
/* ant_bttx_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 63B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45108, 0x3ff4510c
 * Fidelity: high - dual field program verified */
void ant_bttx_cfg(uint8 ant0)
{
    uint8 a = (uint8)(ant0 & 0xffu);
    REG_WRITE(0x3ff45108u, (REG_READ(0x3ff45108u) & 0xf0ffffffu) |
                           (((uint32)(a & 0xfu)) << 24));
    REG_WRITE(0x3ff4510cu, (REG_READ(0x3ff4510cu) & ~0xfu) | a);
}
/* ant_dft_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 39B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c11c
 * Fidelity: high - bit11 RMW verified */
void ant_dft_cfg(bool default_ant)
{
    REG_WRITE(0x3ff5c11cu, (REG_READ(0x3ff5c11cu) & 0xfffff7ffu) |
                           (((uint32)(default_ant & 1u)) << 11));
}
/* ant_rx_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 38B [dwarf-sig]
 * Calls: ant_wifirx_cfg, ant_btrx_cfg | Data refs: ant_btrx_cfg, ant_wifirx_cfg | MMIO: (none)
 * Fidelity: high - fan-out pair verified */
void ant_rx_cfg(bool auto_en, uint8 ant0, uint8 ant1)
{
    ant_wifirx_cfg(auto_en, (uint8)(ant0 & 0xffu), (uint8)(ant1 & 0xffu));
    ant_btrx_cfg(auto_en, (uint8)(ant0 & 0xffu), (uint8)(ant1 & 0xffu));
}
/* ant_tx_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 26B [dwarf-sig]
 * Calls: ant_wifitx_cfg, ant_bttx_cfg | Data refs: ant_bttx_cfg, ant_wifitx_cfg | MMIO: (none)
 * Fidelity: high - fan-out pair verified */
void ant_tx_cfg(uint8 ant0)
{
    uint8 a = (uint8)(ant0 & 0xffu);
    ant_wifitx_cfg(a, a);
    ant_bttx_cfg(a);
}
/* ant_wifirx_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 156B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45104, 0x3ff45108, 0x3ff5c11c
 * Fidelity: medium - 5-lane WiFi-RX antenna program verified; final 0x3ff45108 field exact per re-read */
void ant_wifirx_cfg(bool auto_en, uint8 ant0, uint8 ant1)
{
    uint8 a0 = (uint8)(ant0 & 0xfu), a1 = (uint8)(ant1 & 0xfu);
    REG_WRITE(0x3ff5c11cu, (REG_READ(0x3ff5c11cu) & ~3u) | (((uint32)(auto_en & 1u)) << 1));
    REG_WRITE(0x3ff45104u, (REG_READ(0x3ff45104u) & 0xfffff0ffu) | ((uint32)a0 << 8));
    REG_WRITE(0x3ff45104u, (REG_READ(0x3ff45104u) & 0xf0ffffffu) | ((uint32)a1 << 24));
    REG_WRITE(0x3ff45104u, (REG_READ(0x3ff45104u) & 0xfffff0ffu) | ((uint32)a1 << 8));
    REG_WRITE(0x3ff45108u, (REG_READ(0x3ff45108u) & 0xfff0ffffu) | ((uint32)a1 << 16));
}
/* ant_wifitx_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 70B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45104
 * Fidelity: high - dual field program verified */
void ant_wifitx_cfg(uint8 ant0, uint8 ant1)
{
    uint8 a0 = (uint8)(ant0 & 0xffu), a1 = (uint8)(ant1 & 0xffu);
    REG_WRITE(0x3ff45104u, (REG_READ(0x3ff45104u) & 0xfffff0ffu) |
                           (((uint32)(a0 & 0xfu)) << 8));
    REG_WRITE(0x3ff45104u, (REG_READ(0x3ff45104u) & 0xfff0ffffu) |
                           (((uint32)(a1 & 0xfu)) << 16));
}
/* bb_bss_cbw40 phy_chip_v7.c:2146 @ phy_chip_v7.o size 38B [dwarf-sig]
 * Calls: bb_bss_cbw40_ana, tx_delay_cfg, esp_dport_access_reg_read | Data refs: bb_bss_cbw40_ana, chip7_sleep_params, tx_delay_cfg | MMIO: 0x3ff5c450
 * Fidelity: medium-low - 20MHz lane + call order + mask verified; nonzero (40MHz) lane tail TODO */
void bb_bss_cbw40(int8 sub_chan_cfg)
{
    extern uint8 bb20_shadow;   /* s8i @82 target; exact symbol TODO */
    if (sub_chan_cfg == 0) {                  /* bnez -> 40MHz lane */
        /* 20MHz: indirect hook via table word 28, then ANA + delay cfg. */
        ((void (*)(int8))g_phyFuns[28])(sub_chan_cfg);  /* l32i +112; callx8 */
        bb20_shadow = (uint8)sub_chan_cfg;    /* s8i a2,a8,82 */
        bb_bss_cbw40_ana(sub_chan_cfg);
        tx_delay_cfg(sub_chan_cfg);
    } else {
        /* TODO(40MHz lane at +0x49): see rdis tail past retw. */
        bb_bss_cbw40_ana(sub_chan_cfg);
        tx_delay_cfg(sub_chan_cfg);
    }
    REG_WRITE(0x3ff5c450u, REG_READ(0x3ff5c450u) & ~13u);  /* movi -13 and-lane */
}
/* bb_init phy_chip_v7.c:? @ phy_chip_v7.o size 216B [dwarf-sig]
 * Calls: rc_cal, tx_cap_init, txpwr_offset, tx_pwctrl_init, txiq_cal_init, set_tx_gain_table, write_txrate_power_offset, set_tx_gain_table_bt, tsens_read_init, set_rx_gain_table, analog_gain_init, force_txrxoff, phy_reg_init, chip_v7_set_chan | Data refs: phy_init_flag et al. | MMIO: (via callees + hooks)
 * Fidelity: medium - full init order verified; flag symbol + hook args TODO */
void bb_init(void)
{
    extern uint32 phy_init_flag;   /* bany/bit-test lanes; per funcdb refs */
    if (!(phy_init_flag & 0x10000u)) {           /* bany -> skip */
        ((void (*)(void))g_phyFuns[12])();       /* +48 lane */
        phy_init_flag |= 0x10000u;
    }
    rc_cal();
    if (!(phy_init_flag & 0x80000u)) {           /* bnez -> skip */
        /* hook w69 (+0x114) with (l16+2, l16+0) table lanes; TODO exact. */
        ((void (*)(void))g_phyFuns[69])();
        phy_init_flag |= 0x80000u;
    }
    tx_cap_init();
    txpwr_offset(0);
    tx_pwctrl_init(1);
    txiq_cal_init();
    /* Flag-gated TX-gain path (two l8ui gates at +0x40/+0x44). */
    {
        extern U8 tx_gain_path_flags[2];         /* exact symbols TODO */
        extern uint16 tx_gain_tbl_pair[2];       /* l16ui lanes */
        if (!tx_gain_path_flags[0] || !tx_gain_path_flags[1]) {   /* beqz/bnez lanes */
            set_tx_gain_table(tx_gain_tbl_pair[0], tx_gain_tbl_pair[1]);
            write_txrate_power_offset(0);
            set_tx_gain_table_bt();
        }
    }
    tsens_read_init();
    set_rx_gain_table(0x985, 3);                 /* movi lanes */
    analog_gain_init();
    force_txrxoff(0);
    phy_reg_init();
    /* s16i -128 stamps + default channel 11. */
    chip_v7_set_chan(11, 0);                     /* movi lanes */
}
/* bb_reg_init phy_chip_v7.c:? @ phy_chip_v7.o size 279B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x7 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c024, 0x3ff5c044, 0x3ff5c094, 0x3ff5c400, 0x3ff5cc04, 0x3ff5cc08, 0x3ff5cc0c, 0x3ff5cc48, 0x3ff5ccdc, 0x3ff5cd04, 0x3ff5cd08, 0x3ff5ccd8, 0x3ff5cce4
 * Fidelity: high - 13-lane constant/RMW program verified per disasm */
void bb_reg_init(void)
{
    REG_WRITE(0x3ff5cc48u, 0x170433afu);
    REG_WRITE(0x3ff5cce4u, REG_READ(0x3ff5cce4u) & 0xffbfffffu);
    REG_WRITE(0x3ff5c400u, (REG_READ(0x3ff5c400u) & 0xffff9f00u) | 0x60a5u);
    REG_WRITE(0x3ff5cd04u, 0x51510556u);
    REG_WRITE(0x3ff5cd08u, 0x51510556u);
    REG_WRITE(0x3ff5cc0cu, 0x1241fcu);
    REG_WRITE(0x3ff5cc08u, 0x90b4d20u);
    REG_WRITE(0x3ff5ccdc, 0x195c83cu);
    REG_WRITE(0x3ff5c044u, (REG_READ(0x3ff5c044u) & 0xfe00ffffu) | 0x1fb0000u);
    REG_WRITE(0x3ff5c024u, (REG_READ(0x3ff5c024u) & 0xfffc01ffu) | 0x36800u);
    REG_WRITE(0x3ff5c094u, 0x1b8dd03u);
    REG_WRITE(0x3ff5cc04u, (REG_READ(0x3ff5cc04u) & 0xfffffe03u) | 44u);
    REG_WRITE(0x3ff5ccd8u, 0x186u);
}
/* bb_wdg_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 46B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d03c, 0x3ff5d040
 * Fidelity: high - two constant writes verified */
void bb_wdg_cfg(void)
{
    REG_WRITE(0x3ff5d040u, REG_READ(0x3ff5d040u) | 0x80000000u);
    REG_WRITE(0x3ff5d03cu, 0x401800aau);
}
/* bb_wdt_get_status phy_chip_v7.c:? @ phy_chip_v7.o size 16B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d008
 * Fidelity: high - direct read verified */
uint32 bb_wdt_get_status(void)
{
    return REG_READ(0x3ff5d008u);
}
/* bb_wdt_int_enable phy_chip_v7.c:? @ phy_chip_v7.o size 42B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d040
 * Fidelity: high - bit30 RMW verified */
void bb_wdt_int_enable(bool enable)
{
    REG_WRITE(0x3ff5d040u, (REG_READ(0x3ff5d040u) & 0xbfffffffu) |
                           (((uint32)(enable & 0xffu)) << 30));
}
/* bb_wdt_rst_enable phy_chip_v7.c:? @ phy_chip_v7.o size 36B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d040
 * Fidelity: high - bit31 RMW verified */
void bb_wdt_rst_enable(bool enable)
{
    REG_WRITE(0x3ff5d040u, (REG_READ(0x3ff5d040u) & 0x7fffffffu) |
                           (((uint32)(enable & 0xffu)) << 31));
}
/* bb_wdt_timeout_clear phy_chip_v7.c:? @ phy_chip_v7.o size 27B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d040
 * Fidelity: high - set-bit RMW verified */
void bb_wdt_timeout_clear(void)
{
    REG_WRITE(0x3ff5d040u, REG_READ(0x3ff5d040u) | 0x20000000u);
}
/* bt_bb_to_index phy_chip_v7.c:? @ phy_chip_v7.o size 26B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none - pure map)
 * Fidelity: high - 0/1/2 select verified per disasm */
uint16 bt_bb_to_index(uint16 bbgain)
{
    uint16 v = (uint16)(bbgain & 0xffffu);
    if (v == 0)                           /* beq -> return 0 */
        return 0;
    /* d = v-48; r = (d==0) ? 2 : 1; return r|r = r (moveqz+or lane). */
    return (uint16)(((v - 48) == 0) ? 2 : 1);
}
/* bt_correct_bbgain phy_chip_v7.c:? @ phy_chip_v7.o size 176B [dwarf-sig]
 * Calls: (none) | Data refs: (u16 rodata table via literal) | MMIO: (none)
 * Fidelity: medium-low - copy/search/clamp/adjust structure verified; exact bound arithmetic TODO */
void bt_correct_bbgain(uint16 * bbgain, sint8 * dig_atten_in)
{
    sint8 stage[8];
    for (int i = 0; i < 8; i++)              /* loop a8=8 */
        stage[i] = dig_atten_in[i];
    /* Search stage[] for in-range entry with ±24 window around *bbgain-48
     * (bge/blt vs 48/11 lanes, 3-tap countdown). TODO: exact bounds. */
    uint8 idx = 0; (void)idx;
    uint16 sel;
    if (*bbgain == 0) {
        sel = 32;                            /* movi 32 lane */
    } else {
        /* TODO: search result (a10,a13,a12); table lookup when idx<3. */
        sel = 32;
    }
    *bbgain = sel;                           /* s16i lane */
    /* Adjust first N bytes by delta (a9-counted loop). TODO: exact N/delta. */
    for (int i = 0; i < 8; i++)
        dig_atten_in[i] = (sint8)(dig_atten_in[i] + 0);  /* s8i add lane */
}
/* bt_index_to_bb phy_chip_v7.c:? @ phy_chip_v7.o size 22B [dwarf-sig]
 * Calls: (none) | Data refs: (u16 rodata table via literal) | MMIO: (none)
 * Fidelity: high - range check + table lookup verified */
uint16 bt_index_to_bb(uint16 index)
{
    extern const uint16 bt_idx_table[];   /* l16ui source; exact symbol TODO */
    uint16 i = (uint16)(index & 0xffffu);
    if (i >= 3)                           /* bgeui -> default */
        return 32;
    return bt_idx_table[i];               /* addx2 base+2*i lane */
}
/* bt_opt_write_mem phy_chip_v7.c:? @ phy_chip_v7.o size 117B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x4 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e0c4, 0x3ff4e0c0, 0x3ff4e148
 * Fidelity: high - index/data/strobe program verified per disasm */
void bt_opt_write_mem(uint8 chan_freq, uint8 xtal_dac, uint8 oc_bw)
{
    uint8 idx = (uint8)((((chan_freq & 0xffu) * 3) + 2) & 0xffu);  /* addx2+addi */
    uint32 data;                     /* DWARF l4783 */
    (void)data;
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffffff00u) | idx);
    uint32 w = ((uint32)(xtal_dac & 0xffu) << 24) | ((uint32)(oc_bw & 0xffu) << 16) |
               (REG_READ(0x3ff4e0c0u) & 0xffffu);
    REG_WRITE(0x3ff4e148u, w);
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) | 0x200u);    /* strobe */
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & ~0x200u);   /* 0xfffffdff */
}
/* bt_rx_spur_opt phy_chip_v7.c:? @ phy_chip_v7.o size 331B [dwarf-sig]
 * Calls: set_chan_freq_sw_start x2, rx_spur_cal x3, bt_opt_write_mem x2, esp_dport_access_reg_read | Data refs: (DAC/DCUR vars) | MMIO: 0x3ff4e0c4
 * Fidelity: medium-low - enable/disable lanes + call backbone verified; hook args + DAC values TODO */
void bt_rx_spur_opt(bool enable)
{
    uint8 set_dac, set_dcur;     /* DWARF l4797 */
    uint32 rx_pwr[2]; (void)rx_pwr;  /* DWARF l4798 */
    (void)set_dac; (void)set_dcur;
    if (!(enable & 0xffu)) {                       /* beqz -> 141 lane */
        ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(104, 3, 0, 0);  /* TODO exact */
        ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(102, 4, 0, 0);
        goto tail;
    }
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(104, 3, 0);  /* TODO exact */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(102, 4, 0);
    set_chan_freq_sw_start(44, 0, 0);              /* a10=44 lane; TODO rest */
    rx_spur_cal(0, 0, rx_pwr);                     /* a10=0,a11=0,a12=sp */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(104, 3, 0);
    bt_opt_write_mem(42, 0, 0);                    /* a10=42 lane; TODO rest */
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (102, 4, 5, 7, 6, 0);
    set_chan_freq_sw_start(0, 0, 0);               /* TODO exact args */
    rx_spur_cal(0, 0, rx_pwr);
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(104, 3, 0);
    rx_spur_cal(1, 0, rx_pwr);                     /* a10=1,a11=0 lanes */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(102, 4, 0);
    bt_opt_write_mem(82, 0, 0);                    /* a10=82 lane */
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(104, 3, 0, 0);  /* TODO */
tail:
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffff83ffu) | 0x2c00u);
}
/* bt_tx_gain_cal phy_chip_v7.c:? @ phy_chip_v7.o size 139B [dwarf-sig]
 * Calls: correct_rf_ana_gain_new (per-iter) | Data refs: (gain tables via literals) | MMIO: (none)
 * Fidelity: medium-low - iterate-and-clamp loop verified; table roles TODO */
void bt_tx_gain_cal(void)
{
    extern U8 bt_gain_tbl[];   /* s8i +120/+129 lanes; exact symbol TODO */
    /* Iterate gain entries (12-step counters wrapping to 0): per entry call
     * correct_rf_ana_gain_new() with staged stack args, clamp result to
     * [0,64] (bgez/bge lanes), store bytes. TODO: exact staging. */
    for (int i = 0; i < 8; i++) {            /* a6: 160+12k mod 256 wraps to 0 */
        correct_rf_ana_gain_new();
        int8 v = 0;                          /* TODO: computed value lane */
        bt_gain_tbl[i] = (uint8)(v < 0 ? 0 : (v > 64 ? 64 : v));
    }
}
/* bt_tx_gain_cal_set phy_chip_v7.c:? @ phy_chip_v7.o size 16B [dwarf-sig]
 * Calls: bt_tx_gain_cal_set$part$4 (local direct call8) | Data refs: (flag byte) | MMIO: (none)
 * Fidelity: high - flag-gated part call verified */
void bt_tx_gain_cal_set(void)
{
    extern U8 bt_tx_gain_cal_needed;   /* l8ui gate; exact symbol TODO */
    if (bt_tx_gain_cal_needed)         /* bnez -> return */
        return;
    bt_tx_gain_cal_set$part$4();   /* local call8; GCC $ extension */
}
/* bt_tx_gain_cal_set$part$4 phy_chip_v7.c:? @ phy_chip_v7.o size 38B [dwarf-sig-base]
 * Calls: bt_tx_gain_cal, force_txrx_off, wr_bt_tx_gain_mem, wr_bt_tx_atten | Data refs: (atten table via literal) | MMIO: (none)
 * Fidelity: medium - call order + args verified per disasm + relocs */
void bt_tx_gain_cal_set$part$4(void)
{
    extern sint8 bt_default_atten[];   /* atten table literal; exact symbol TODO */
    extern void force_txrx_off(int en);   /* distinct from force_txrxoff; defined outside libphy scope */
    bt_tx_gain_cal();                  /* local direct call8 */
    force_txrx_off(1);                 /* movi a10,1 lane */
    wr_bt_tx_gain_mem(255, 255);       /* movi lanes */
    wr_bt_tx_atten(bt_default_atten);  /* l32r table lane */
    force_txrx_off(0);                 /* movi a10,0 lane */
}
/* bt_txdc_cal phy_chip_v7.c:? @ phy_chip_v7.o size 19B [dwarf-sig]
 * Calls: bt_txdc_cal$part$5 (local) | Data refs: (status word via literal) | MMIO: (none)
 * Fidelity: high - bit12-gated part call verified */
void bt_txdc_cal(void)
{
    extern uint32 bt_cal_status;   /* bbsi 12 source; exact symbol TODO */
    if (bt_cal_status & 0x1000u)   /* bbsi -> return (already done) */
        return;
    bt_txdc_cal$part$5();
}
/* bt_txdc_cal$part$5 phy_chip_v7.c:? @ phy_chip_v7.o size 169B [dwarf-sig-base]
 * Calls: (indirect) g_phyFuns[48,54,47,46,28,52,49] | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium-low - hook order + copy loop + finale verified; table words per disasm offsets */
void bt_txdc_cal$part$5(void)
{
    ((void (*)(void))g_phyFuns[48])();                 /* +192 lane */
    ((void (*)(void))g_phyFuns[54])();                 /* +216 lane */
    ((void (*)(uint32, uint32))g_phyFuns[47])(1, 1);   /* +188 lane */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(1, 2, 0);  /* +184 */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(1, 2, 0);
    ((void (*)(void *))g_phyFuns[28])(0);              /* +0x118 lane */
    /* 4x l16 copy loop with beq-bound inner. TODO exact. */
    for (int i = 0; i < 4; i++) {                     /* approximate */
    }
    ((void (*)(void))g_phyFuns[52])();                 /* +208 lane */
    ((void (*)(void))g_phyFuns[49])();                 /* +196 lane */
    extern uint32 bt_txdc_done_flag;                   /* or 0x1000 lane */
    bt_txdc_done_flag |= 0x1000u;
}
/* bt_txiq_cal phy_chip_v7.c:? @ phy_chip_v7.o size 19B [dwarf-sig]
 * Calls: bt_txiq_cal$part$6 (local) | Data refs: (status word via literal) | MMIO: (none)
 * Fidelity: high - bit11-gated part call verified */
void bt_txiq_cal(void)
{
    extern uint32 bt_cal_status;   /* bbsi 11 source; exact symbol TODO */
    if (bt_cal_status & 0x800u)    /* bbsi -> return (already done) */
        return;
    bt_txiq_cal$part$6();
}
/* bt_txiq_cal$part$6 phy_chip_v7.c:? @ phy_chip_v7.o size 166B [dwarf-sig-base]
 * Calls: rfcal_txiq (per step) | Data refs: tx_rf_ana_gain, chip7_sleep_params+92/+98/+0, .rodata.CSWTCH$356 (relocs) | MMIO: (none)
 * Fidelity: medium - painter pair, clamp [0,120], stepped rfcal loop verified; table roles TODO */
void bt_txiq_cal$part$6(void)
{
    extern uint16 tx_rf_ana_gain[];  /* painter sources */
    extern uint8 chip7_sleep_params[];
    /* Per step (a2 += 2 until bound): paint two 6-bit-weighted values,
     * diff vs (sleep[116]+43), clamp [0,120], rfcal_txiq() stage call. */
    for (int step = 0; ; step++) {               /* beq-bound; TODO bound */
        /* TODO: painter pair (6-bit-weighted from tx_rf_ana_gain/CSWTCH),
         * diff, clamp [0,120], rfcal_txiq() stage call per step. */
        rfcal_txiq();
        if (step >= 4)                           /* approximate bound */
            break;
    }
    *(uint32 *)chip7_sleep_params |= 0x800u;     /* or-lane finale */
}
/* btpwr_backoff phy_chip_v7.c:? @ phy_chip_v7.o size 100B [dwarf-sig]
 * Calls: wr_bt_tx_atten | Data refs: (table + flag via literals) | MMIO: (none)
 * Fidelity: medium - 8-tap clamp loop + atten write verified; table/flag symbols TODO */
void btpwr_backoff(s8 backoff)
{
    extern U8 bt_att_tbl[8];   /* l8ui/s8i +129 lane; exact symbol TODO */
    extern U8 bt_att_base;     /* subtrahend lane */
    extern U8 bt_att_flag;     /* s8i store lane */
    uint8 d = (uint8)(((uint8)backoff - bt_att_base) & 0xffu);
    for (int i = 0; i < 8; i++) {              /* loop a10=8 */
        uint8 b = (uint8)((bt_att_tbl[i] + d) & 0xffu);
        int8 s = (int8)b;                      /* sext 7 */
        if (s < 0)                             /* bgez -> keep path */
            bt_att_tbl[i] = 0;
        else
            bt_att_tbl[i] = (s > 64) ? 64 : b; /* blt 64 lane */
    }
    wr_bt_tx_atten((sint8 *)bt_att_tbl);
    bt_att_flag = (uint8)backoff;
}
/* chan14_mic_cfg phy_chip_v7.c:4460 @ phy_chip_v7.o size 238B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_set_most_tpw | Data refs: phy_set_most_tpw | MMIO: 0x3ff5c400
 * Fidelity: medium-low - set_en==1 lane (RMW + two word-42 indirect writes) verified; clear lane TODO */
void chan14_mic_cfg(u8 set_en)
{
    if (set_en != 1)
        goto clear_lane;                     /* bnei -> +0x6e; TODO */
    REG_WRITE(0x3ff5c400u, (REG_READ(0x3ff5c400u) & 0xffff9fffu) | 0x2000u);
    /* Two ordered writes through g_phyFuns word 42 (+168). */
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (103, 3, 6, 0, 76, set_en);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (103, 4, 6, 0, 78, set_en);
    phy_set_most_tpw();                      /* reloc-verified tail call */
    return;
clear_lane:
    /* TODO: mirror-image clear sequence at +0x6e. */
    phy_set_most_tpw();
}
/* chan14_mic_enable phy_chip_v7.c:? @ phy_chip_v7.o size 89B [dwarf-sig]
 * Calls: chan14_mic_cfg (en==0 lane) | Data refs: chan14_mic_en, chan14_mic_flag, phy_in_most_power, phy_in_most_power_bk, chan14_mic_most_power (relocs) | MMIO: (none)
 * Fidelity: high - flag/backup/min-store sequence verified per disasm + relocs */
void chan14_mic_enable(bool en, s8 most_pwr)
{
    extern U8 chan14_mic_en, chan14_mic_flag, phy_in_most_power,
              phy_in_most_power_bk, chan14_mic_most_power;
    chan14_mic_en = (uint8)(en & 0xffu);      /* s8i lane */
    if (!chan14_mic_en) {                     /* bnez -> set lane */
        chan14_mic_cfg(0);
        return;
    }
    if (!chan14_mic_flag) {                   /* bnez -> min lane */
        chan14_mic_flag = 1;
        phy_in_most_power_bk = phy_in_most_power;  /* backup lane */
    }
    int8 mp = (int8)most_pwr;                 /* sext 7 */
    chan14_mic_most_power = (uint8)(mp < 48 ? mp : 48);  /* min 48 lane */
}
/* chip_sleep_prot_dis phy_chip_v7.c:2114 @ phy_chip_v7.o size 37B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[3], esp_dport_access_reg_read | Data refs: g_phyFuns (reloc) | MMIO: 0x60033cb8
 * Fidelity: high - hook + mask RMW verified */
void chip_sleep_prot_dis(void)
{
    ((void (*)(void))g_phyFuns[3])();            /* +12 lane */
    REG_WRITE(0x60033cb8u, REG_READ(0x60033cb8u) & 0xf8007fffu);
}
/* chip_sleep_prot_en phy_chip_v7.c:2100 @ phy_chip_v7.o size 114B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us, (indirect) g_phyFuns[2] | Data refs: g_phyFuns (reloc) | MMIO: 0x60033cb8
 * Fidelity: high - set + delay-poll + set + hook verified */
void chip_sleep_prot_en(void)
{
    REG_WRITE(0x60033cb8u, REG_READ(0x60033cb8u) | 0x8000u);
    do {
        ets_delay_us(2);
    } while (REG_READ(0x60033cb8u) & 0x6000u);   /* bany lane */
    REG_WRITE(0x60033cb8u, REG_READ(0x60033cb8u) | 0x7ff8000u);
    ((void (*)(void))g_phyFuns[2])();            /* +8 lane */
}
/* chip_v7_rxmax_ext phy_chip_v7.c:2190 @ phy_chip_v7.o size 5B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void chip_v7_rxmax_ext(uint8 ext_level)
{
    return;
}

/* chip_v7_rxmax_ext_dig phy_chip_v7.c:2177 @ phy_chip_v7.o size 5B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void chip_v7_rxmax_ext_dig(uint8 ext_level)
{
    return;
}

/* chip_v7_set_chan_misc phy_chip_v7.c:2561 @ phy_chip_v7.o size 123B [dwarf-sig]
 * Calls: wr_rx_gain_mem, set_chan_rxcomp, set_chan_dig_gain | Data refs: chip7_sleep_params, set_chan_dig_gain, set_chan_rxcomp, wr_rx_gain_mem | MMIO: (none)
 * Fidelity: medium-low - flag-gated lanes + call order verified; flag symbols + hook word 91 args TODO */
void chip_v7_set_chan_misc(int8 channel)
{
    extern uint8 misc_flag_a, misc_flag_b;   /* l8ui lanes; exact symbols TODO */
    (void)channel;
    /* Indirect opener via table word 33 (l32i +132) with (chan, sleep78). */
    ((void (*)(int8, int16))g_phyFuns[33])(channel, misc_hook_arg());
    if (misc_flag_a == 0 || misc_flag_b == 0) {
        wr_rx_gain_mem(0, (uint8)(misc_flag_b + 1));  /* a10=0,a11=flag+1 lane */
    }
    set_chan_rxcomp(0);
    /* Indirect via table word 91 (l32i +0x16c), then conditional dig gain. */
    g_phyFuns_hook91(channel);
    if (misc_flag_a == 0 || misc_flag_b == 0) {
        set_chan_dig_gain((uint8)channel);
    }
}
/* disable_wifi_agc phy_chip_v7.c:107 @ phy_chip_v7.o size 102B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c01c, 0x3ff5c030, 0x3ff5c038, 0x3ff5c080
 * Fidelity: high - linear RMW chain fully verified per disasm */
void disable_wifi_agc(void)
{
    REG_WRITE(0x3ff5c01c, (REG_READ(0x3ff5c01c) & 0xff00ffffu) | 0x7f0000u);
    REG_WRITE(0x3ff5c038, REG_READ(0x3ff5c038) | 0x4000000u);
    REG_WRITE(0x3ff5c030, REG_READ(0x3ff5c030) & 0xffffffcfu);  /* & -49 */
    REG_WRITE(0x3ff5c080, REG_READ(0x3ff5c080) | 1u);
}
/* enable_wifi_agc phy_chip_v7.c:115 @ phy_chip_v7.o size 105B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c01c, 0x3ff5c030, 0x3ff5c038, 0x3ff5c080
 * Fidelity: high - linear RMW chain fully verified per disasm */
void enable_wifi_agc(void)
{
    REG_WRITE(0x3ff5c080, REG_READ(0x3ff5c080) & ~1u);          /* movi -2 and-lane */
    REG_WRITE(0x3ff5c030, (REG_READ(0x3ff5c030) & ~0x30u) | 16u);
    REG_WRITE(0x3ff5c01c, (REG_READ(0x3ff5c01c) & 0xff00ffffu) | 0xc0000u);
    REG_WRITE(0x3ff5c038, REG_READ(0x3ff5c038) | 0x4000000u);
}
/* esp_tx_state_out phy_chip_v7.c:? @ phy_chip_v7.o size 193B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x7 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff44530+ GPIOs, 0x3ff45104, 0x3ff45108, 0x3ff45110
 * Fidelity: high - GPIO mux pair + shared tail verified per disasm */
void esp_tx_state_out(uint8 wifi_gpio_num, uint8 bt_gpio_num)
{
    uint8 w = (uint8)(wifi_gpio_num & 0xffu), b = (uint8)(bt_gpio_num & 0xffu);
    REG_WRITE(0x3ff44530u + 4u * w, (REG_READ(0x3ff44530u + 4u * w) & ~0x1ffu) | 222u);
    uint32 flag = 0x80000000u;
    /* NOTE: movi a5,128/64 lanes have no dataflow (dead setups). */
    if (w != b) {                                /* beq -> shared */
        REG_WRITE(0x3ff44530u + 4u * b, (REG_READ(0x3ff44530u + 4u * b) & ~0x1ffu) | 223u);
        flag = 0x40000000u;
    }
    REG_WRITE(0x3ff45104u, (REG_READ(0x3ff45104u) & 0x3f3f3f3fu) | 0x404000u);
    REG_WRITE(0x3ff45108u, (REG_READ(0x3ff45108u) & 0x3f3f3f3fu) | flag);
    REG_WRITE(0x3ff45110u, REG_READ(0x3ff45110u) & ~193u);  /* movi -193 */
}
/* fe_reg_init phy_chip_v7.c:? @ phy_chip_v7.o size 175B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x7 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff450d8, 0x3ff450dc, 0x3ff45114, 0x3ff4604c, 0x3ff4609c, 0x3ff460a0, 0x3ff460b8
 * Fidelity: high - 7-lane front-end program verified (incl. cross-reg 460b8->4609c lane) */
void fe_reg_init(void)
{
    REG_WRITE(0x3ff460a0u, REG_READ(0x3ff460a0u) | 0x1000000u);
    REG_WRITE(0x3ff45114u, REG_READ(0x3ff45114u) | 0x200u);
    REG_WRITE(0x3ff450dcu, REG_READ(0x3ff450dcu) | 0xc0000000u);
    REG_WRITE(0x3ff450d8u, REG_READ(0x3ff450d8u) | 0x2000000u);
    REG_WRITE(0x3ff4609cu, REG_READ(0x3ff460b8u) | 0x2000000u);
    REG_WRITE(0x3ff4609cu, REG_READ(0x3ff4609cu) | 0x4000u);
    REG_WRITE(0x3ff4604cu, (REG_READ(0x3ff4604cu) & 0xffff00ffu) | 0xc800u);
}
/* force_bttx_gain phy_chip_v7.c:? @ phy_chip_v7.o size 139B [dwarf-sig]
 * Calls: wr_bt_tx_gain_mem, wr_bt_tx_atten | Data refs: (two flag bytes via literals) | MMIO: (none)
 * Fidelity: high - fill/commit/clear lanes verified per disasm */
void force_bttx_gain(bool force_en, uint8 pa_in, uint8 bb_in, uint8 dig_in)
{
    extern U8 bttx_force_flag, bttx_force_flag2;  /* s8i targets */
    extern sint8 bt_default_atten_tbl[];          /* +8 lane */
    if (!(force_en & 0xffu)) {               /* beqz -> 75 lane */
        bttx_force_flag2 = 1;
        bttx_force_flag = 0;                 /* s8i a2(=0) lane */
        wr_bt_tx_atten(bt_default_atten_tbl);  /* a10=table,a11=255 lanes */
        return;
    }
    uint8 d = (uint8)(dig_in & 0xffu);
    uint8 cells[8];
    for (int i = 0; i < 8; i++)              /* loop a8=8 */
        cells[i] = d;
    wr_bt_tx_gain_mem((uint8)(pa_in & 0xffu), (uint8)(bb_in & 0xffu));
    bttx_force_flag = 0;
    wr_bt_tx_atten((sint8 *)cells);
    bttx_force_flag = 1;
    bttx_force_flag2 = 0;
}
/* freq_offset_get_pwr_1 phy_chip_v7.c:? @ phy_chip_v7.o size 472B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, get_iq_est_snr_1, phy_printf | Data refs: (tables via literals) | MMIO: 0x3ff450a8, 0x3ff460b8
 * Fidelity: medium-low - program + measure/accumulate loop + combine verified; bit surgery TODO */
uint64 freq_offset_get_pwr_1(U8 loop_bits, S16 tone_step, U8 corr_cycle_bits, uint64 * tot_pwr_o, bool rxiq_sign, bool print_en)
{
    U8 loop_i; (void)loop_i;                 /* DWARF l4682 */
    uint64 get_power[2]; (void)get_power;    /* DWARF l4683 */
    uint64 pwr_sum = 0, tot_pwr = 0;         /* DWARF l4684 */
    (void)loop_bits; (void)tone_step; (void)corr_cycle_bits;
    (void)rxiq_sign; (void)print_en;
    /* Program 0x3ff450a8/0x3ff460b8 lanes, then per-iteration (loop_bits
     * count): table hook +0x144, get_iq_est_snr_1(), 64-bit accumulate
     * with carry, hook +0x148, optional printf. */
    for (loop_i = 0; loop_i < loop_bits; loop_i++) {
        /* TODO: exact per-iter ops from rdis. */
        pwr_sum += get_power[0];
        tot_pwr += get_power[1];
    }
    /* Bit-field combine (ssr/srl lanes), store, restore MMIO, return. */
    tot_pwr_o[0] = pwr_sum;
    tot_pwr_o[1] = tot_pwr;
    REG_WRITE(0x3ff460b8u, REG_READ(0x3ff460b8u) & 0xfffbffffu);
    return tot_pwr;
}
/* get_bbgain_db phy_chip_v7.c:? @ phy_chip_v7.o size 38B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none - bit loop)
 * Fidelity: high - 6-tap bit-weighted sum verified per disasm */
uint8 get_bbgain_db(uint16 bbgain)
{
    uint8 lo = (uint8)(bbgain & 0x3fu);
    uint8 acc = 0;
    uint8 base = (uint8)((bbgain >> 6) & 0xffu);
    for (int i = 0; i < 6; i++) {              /* loop a9=6 */
        uint8 step = (uint8)((acc + 6) & 0xffu);
        if (!(lo & (1u << i)))                 /* bbc lane */
            step = acc;                        /* keep when bit clear */
        acc = step;                            /* extui lane */
        base = (uint8)((base + acc) & 0xffu);
    }
    return base;
}
/* get_iq_est_snr_1 phy_chip_v7.c:4626 @ phy_chip_v7.o size 1062B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, __divdi3, phy_printf | Data refs: .rodata.str1.4, __divdi3, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff46080, 0x3ff46084, 0x3ff46088, 0x3ff4608c, 0x3ff460cc, 0x3ff460d0, 0x3ff460d4, 0x3ff460d8, 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_iq_est_snr_1(uint64 * get_power, uint8 shift_bits, bool print_en)
{
    (void)get_power;
    (void)shift_bits;
    (void)print_en;
    /* DWARF locals: sint64 sig1_i@l4628, sint64 sig1_q@l4628, sint64 sig2_i@l4628, sint64 sig2_q@l4628, sint64 sig12_i@l4628, sint64 sig12_q@l4628, sint64 dc_i@l4628, sint64 dc_q@l4628, uint64 sig_power@l4629, uint64 dc_power@l4629, uint64 total_power@l4629, sint64 noise_power@l4630, const int32 cw_rms@l4631, uint8 pwr_lshift@l4635 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <get_iq_est_snr_1> (405 insns) + DWARF line rows for phy_chip_v7.c:4626.
     * Ordered callee relocs: esp_dport_access_reg_read, __divdi3, phy_printf.
     */
}

/* get_iq_value phy_chip_v7.c:? @ phy_chip_v7.o size 42B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none - bit split)
 * Fidelity: high - signed 5/6-bit field split verified */
void get_iq_value(sint8 * iq_out, uint16 iq_in)
{
    uint16 v = (uint16)(iq_in & 0xffffu);
    int8 hi = (int8)((v >> 6) & 0x1fu);
    if (hi > 15)                             /* bge 15 -> wrap */
        hi -= 32;                            /* s5 wrap */
    iq_out[0] = (sint8)hi;                   /* s8i lane */
    int8 lo = (int8)(v & 0x3fu);
    if (lo > 31)                             /* bge 31 -> wrap */
        lo -= 64;                            /* s6 wrap */
    iq_out[1] = (sint8)lo;
}
/* get_phy_version_str phy_chip_v7.c:? @ phy_chip_v7.o size 31B [dwarf-sig]
 * Calls: sprintf | Data refs: sprintf | MMIO: (none)
 * Fidelity: medium - call + 0x12ff version lane verified; buffer/format/arg symbols TODO */
char * get_phy_version_str(void)
{
    extern char ver_buf[];        /* exact symbol TODO */
    extern const char ver_fmt[];  /* 0xd4 lane; exact symbol TODO */
    extern int ver_a, ver_b, ver_c;  /* 0xe0/0xec/0xf4 lanes; TODO */
    sprintf(ver_buf, ver_fmt, ver_a, ver_b, 0x12ff, ver_c);
    return ver_buf;               /* a10=buf at ret */
}
/* get_spur4m_pwr phy_chip_v7.c:? @ phy_chip_v7.o size 201B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x4, freq_offset_get_pwr_1 x2 | Data refs: | MMIO: 0x3ff5c02c
 * Fidelity: medium - program + dual-measure + 64-bit combine + restore verified; out-pack lane approximate */
void get_spur4m_pwr(uint32 * out_pwr)
{
    REG_WRITE(0x3ff5c02cu, (REG_READ(0x3ff5c02cu) & ~0xffffffu) | 0x3c000000u);
    REG_WRITE(0x3ff5c02cu, REG_READ(0x3ff5c02cu) | 0x800000u);
    uint64 stack_tmp[2]; (void)stack_tmp;   /* tot_pwr_o spill lane */
    /* r = meas(5, tone, 10, sp, 0, 0); tone -103 then -102. */
    uint64 r1 = freq_offset_get_pwr_1(5, -103, 10, &stack_tmp[0], false, false);
    uint64 r2 = freq_offset_get_pwr_1(5, -102, 10, &stack_tmp[0], false, false);
    uint64 sum = r1 + r2;                    /* carry-chain add lane */
    /* Pack halves: out[0] = (hi1<<15)|(lo>>17)... TODO exact interleave. */
    out_pwr[0] = (uint32)(sum & 0xffffffffu);
    out_pwr[1] = (uint32)(sum >> 32);
    REG_WRITE(0x3ff5c02cu, (REG_READ(0x3ff5c02cu) & ~0xffffffu) | 0x32000000u);
    REG_WRITE(0x3ff5c02cu, REG_READ(0x3ff5c02cu) | 0x800000u);  /* approx */
    REG_WRITE(0x3ff5c02cu, REG_READ(0x3ff5c02cu) & ~0x8000000u);  /* 0xff7fffff */
}
/* i2c_master_reset phy_chip_v7.c:? @ phy_chip_v7.o size 90B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff4e000+4i, 0x60033c00
 * Fidelity: medium - 5-lane busy-wait with timer-bounded timeout write verified; exact branch plumbing has one ambiguous target (see note) */
void i2c_master_reset(void)
{
    /* NOTE: branch-target plumbing around the timeout lane (+0x18/+0x38)
     * is ambiguous in linear disasm; below is the only sane reading:
     * per-lane busy-wait with a 3-tick timeout that prints + writes 0. */
    for (int i = 0; i < 5; i++) {                /* bnei 5 lane */
        uint32 addr = 0x3ff4e000u + 4u * (uint32)i;
        uint32 t0 = REG_READ(0x60033c00u);
        while (REG_READ(addr) & 0x2000000u) {    /* bany lane */
            if (REG_READ(0x60033c00u) - t0 >= 3u) {  /* bltui 3 lane */
                phy_printf();                    /* timeout diagnostic */
                REG_WRITE(addr, 0);              /* s32i a7 lane */
            }
        }
    }
}
/* i2cmst_reg_init phy_chip_v7.c:? @ phy_chip_v7.o size 143B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e0c4
 * Fidelity: high - 5-lane master-init program verified */
void i2cmst_reg_init(void)
{
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xfff0ffffu) | 0x20000u);
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xff0fffffu) | 0x400000u);
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) | 0x1000000u);
    REG_WRITE(0x3ff4e0c4u, REG_READ(0x3ff4e0c4u) & 0xdfffffffu);
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffff83ffu) | 0x2c00u);
}
/* mac_enable_bb phy_chip_v7.c:? @ phy_chip_v7.o size 130B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x7 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff00024
 * Fidelity: high - 7-op set/clear pulse dance verified per disasm */
void mac_enable_bb(void)
{
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) | 0x10000000u);
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) & ~3u);   /* movi -3 lane */
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) | 2u);
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) & ~3u);
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) | 2u);
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) & ~3u);
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) | 2u);
}
/* noise_check_loop phy_chip_v7.c:? @ phy_chip_v7.o size 344B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x6 | Data refs: (noise tables via literals) | MMIO: 0x3ff5c018, 0x3ff5c050, 0x3ff5d044, 0x3ff5d050
 * Fidelity: medium-low - program + biased read + level state machine verified; select arithmetic TODO */
void noise_check_loop(uint8 check_level, bool set_noise_en)
{
    sint16 noise_value, current_value, reg_value;  /* DWARF l2393 */
    bool set_noise_flag; (void)set_noise_flag;     /* DWARF l2394 */
    (void)check_level;
    REG_WRITE(0x3ff5d044u, REG_READ(0x3ff5d044u) & ~2u);
    REG_WRITE(0x3ff5d050u, REG_READ(0x3ff5d050u) | 1u);
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) | 0x8000000u);
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) & ~0x8000000u);
    /* Biased noise read + clamp (like ram_phy_get_noisefloor). */
    noise_value = (sint16)(((REG_READ(0x3ff5c050u) & 0x3ffu) - 1024) & 0xffff);
    current_value = noise_value;                   /* TODO exact flow */
    reg_value = current_value;
    /* Level-tracking state machine with s16i stores (+178/+78 slots)
     * and optional table hook +132 when set_noise_en. TODO exact law. */
    if (set_noise_en & 0xffu) {
        ((void (*)(uint32))g_phyFuns[33])((uint32)(uint16)current_value);
    }
    (void)reg_value;
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) | 1u);  /* finale lane */
}
/* noise_init phy_chip_v7.c:? @ phy_chip_v7.o size 259B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, chip_v7_set_chan_nomac | Data refs: (noise tables via literals) | MMIO: 0x3ff5c018
 * Fidelity: medium-low - program + 3-channel measure/min-track + reduce verified; hook slots + table roles TODO */
void noise_init(void)
{
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) | 0x10000000u);
    REG_WRITE(0x3ff5c018u, (REG_READ(0x3ff5c018u) & ~8u) | 4u);
    /* Per-channel (3x, bnei-bounded): set_chan_nomac() after hook+128 table
     * staging, noise read, min-track with shift/or bit lanes. TODO exact. */
    for (int ch = 0; ch < 3; ch++) {             /* approximate trip form */
        chip_v7_set_chan_nomac(0, 0);            /* TODO exact args */
        /* TODO: hook+128 read, min-track lanes. */
    }
    /* Min-reduce across channels, s16i stores, final table hook +132. */
    ((void (*)(void))g_phyFuns[33])();           /* +132 lane */
}
/* opt_11b_resart phy_chip_v7.c:? @ phy_chip_v7.o size 138B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c01c, 0x3ff5c094, 0x3ff5c0a0, 0x3ff5c0b8, 0x3ff5c0f0
 * Fidelity: high - 5-lane 11b-mode program verified per disasm */
void opt_11b_resart(void)
{
    REG_WRITE(0x3ff5c0a0u, (REG_READ(0x3ff5c0a0u) & 0xff00ffffu) | 0x800000u);
    REG_WRITE(0x3ff5c01cu, (REG_READ(0x3ff5c01cu) & 0xff00ffffu) | 0xc0000u);
    REG_WRITE(0x3ff5c094u, (REG_READ(0x3ff5c094u) & 0xffff01ffu) | 0xdc00u);
    REG_WRITE(0x3ff5c0f0u, (REG_READ(0x3ff5c0f0u) & 0xffffff00u) | 0xdc00u);
    REG_WRITE(0x3ff5c0b8u, (REG_READ(0x3ff5c0b8u) & 0xffffff00u) | 128u);
    REG_WRITE(0x3ff5c0b8u, REG_READ(0x3ff5c0b8u) | 0x800u);
}
/* pbus_print phy_chip_v7.c:? @ phy_chip_v7.o size 187B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[47] x7, phy_printf x4 | Data refs: g_phyFuns, phy_printf | MMIO: (none direct)
 * Fidelity: medium - 7 reads + 4 prints sequence verified per disasm; fmt literals TODO */
void pbus_print(void)
{
    /* g_phyFuns[47] (+188) reads with (a10,a11) lanes verified. */
    uint32 r0 = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(0, 1);
    uint32 r1 = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(4, 1);
    (void)r0;
    phy_printf();                              /* fmt 0x238 lane */
    uint32 r2 = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(5, 1);
    uint32 r3 = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(1, 1);
    (void)r1; (void)r2; (void)r3;
    phy_printf();                              /* fmt 0x244 lane */
    uint32 r4 = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(2, 1);
    uint32 r5 = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(3, 1);
    (void)r4; (void)r5;
    phy_printf();                              /* fmt 0x254 lane */
    uint32 r6 = ((uint32 (*)(uint32, uint32))g_phyFuns[47])(3, 2);
    (void)r6;
    phy_printf();                              /* fmt 0x264 lane */
}
/* phy_ant_init phy_chip_v7.c:? @ phy_chip_v7.o size 71B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c030, 0x3ff5c11c, 0x3ff5c120
 * Fidelity: high - three constant programs verified */
void phy_ant_init(void)
{
    REG_WRITE(0x3ff5c030u, (REG_READ(0x3ff5c030u) & 0xfffc07ffu) | 0x1a000u);
    REG_WRITE(0x3ff5c11cu, 0xe000u);
    REG_WRITE(0x3ff5c120u, 0x1e101e1cu);
}
/* phy_bttx_low_power phy_chip_v7.c:? @ phy_chip_v7.o size 161B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40] x2, g_phyFuns[91], force_bttx_gain | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium - lane structure + mask loop + force call verified; w91 hook args + bb residue TODO */
void phy_bttx_low_power(bool force_en, uint8 level)
{
    extern uint32 w91_chip_id;   /* hook arg literal; exact symbol TODO */
    extern uint8 chip7_sleep_params[];
    uint8 lv = (uint8)(level & 0xffu);
    uint8 mask;
#define W91() ((void (*)(uint32, uint8))g_phyFuns[91])(w91_chip_id, chip7_sleep_params[81])
    if (lv >= 6) {                               /* bgeui -> hi lane */
        W91();
        mask = 15;                               /* 4-bit loop result */
    } else if (!force_en && lv != 0) {           /* beq/bne -> 51 lane */
        W91();
        mask = (uint8)((1u << (lv - 1)) - 1);    /* bit-loop result */
    } else {
        ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 1, 96);
        ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(107, 2, 2, 0);
        mask = 0;
    }
    force_bttx_gain(lv, mask, 0, 40);   /* a10=level,a11=mask,a12=0,a13=40 lanes */
}
/* phy_byte_to_word phy_chip_v7.c:? @ phy_chip_v7.o size 35B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none - LE assemble)
 * Fidelity: high - byte assemble verified */
uint32 phy_byte_to_word(uint8 * data)
{
    return ((uint32)data[0]) | ((uint32)data[1] << 8) |
           ((uint32)data[2] << 16) | ((uint32)data[3] << 24);
}
/* phy_cal_print phy_chip_v7.c:4934 @ phy_chip_v7.o size 974B [dwarf-sig]
 * Calls: phy_printf, esp_dport_access_reg_read | Data refs: .rodata.str1.4, chip7_sleep_params, esp_dport_access_reg_read, noise_array, phy_printf, phy_rxbb_dc, phy_rxrf_dc, tx_rf_ana_gain | MMIO: 0x3ff5a004, 0x3ff5a008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void phy_cal_print(void)
{
    /* DWARF locals: uint8 i@l4936, sint32 temp@l4937, s8 iq_mg@l4938, s8 iq_mp@l4938, u32 loop_i@l4939, uint16 * txdc@l4940, sint16[] rxdc@l4941, u8 rfrx_index@l4942, u16 bbgain@l4943, bool print_en@l4944, u32 vdd33@l4949, s8 vdd33_offset@l4950, u8 temp_code@l4951 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <phy_cal_print> (344 insns) + DWARF line rows for phy_chip_v7.c:4934.
     * Ordered callee relocs: phy_printf, esp_dport_access_reg_read.
     */
}

/* phy_chan_dump_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 160B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5cd0c
 * Fidelity: high - 5-lane dump-enable program verified */
void phy_chan_dump_cfg(bool shift_force_en, uint8 shift_force, bool lltf_dump_en, bool htltf_dump_en, bool stbcltf2_dump_en)
{
    REG_WRITE(0x3ff5cd0cu, (REG_READ(0x3ff5cd0cu) & ~9u) | (((uint32)(shift_force_en & 1u)) << 3));
    REG_WRITE(0x3ff5cd0cu, (REG_READ(0x3ff5cd0cu) & ~0xf0u) | (((uint32)(shift_force & 0xffu) << 4) & 0xffu));
    REG_WRITE(0x3ff5cd0cu, (REG_READ(0x3ff5cd0cu) & ~3u) | (((uint32)(lltf_dump_en & 1u)) << 1));
    REG_WRITE(0x3ff5cd0cu, (REG_READ(0x3ff5cd0cu) & ~1u) | ((uint32)(htltf_dump_en & 1u)));
    REG_WRITE(0x3ff5cd0cu, (REG_READ(0x3ff5cd0cu) & ~5u) | (((uint32)(stbcltf2_dump_en & 1u)) << 2));
}
/* phy_chan_filt_set phy_chip_v7.c:? @ phy_chip_v7.o size 205B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x7 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c074, 0x3ff5cc0c, 0x3ff5cd04, 0x3ff5cd08
 * Fidelity: high - filter/merge lanes verified per disasm */
void phy_chan_filt_set(bool filt_en, bool merge_en)
{
    if (filt_en & 0xffu) {                       /* beqz -> else lane */
        REG_WRITE(0x3ff5cc0cu, REG_READ(0x3ff5cc0cu) & ~0x200000u);
        REG_WRITE(0x3ff5cc0cu, REG_READ(0x3ff5cc0cu) & ~0x400000u);
    } else {
        REG_WRITE(0x3ff5cc0cu, REG_READ(0x3ff5cc0cu) | 0x200000u);
        REG_WRITE(0x3ff5cc0cu, REG_READ(0x3ff5cc0cu) | 0x400000u);
    }
    REG_WRITE(0x3ff5cd08u, REG_READ(0x3ff5cd08u) & ~8u);   /* movi -8 */
    REG_WRITE(0x3ff5cd04u, REG_READ(0x3ff5cd04u) & ~8u);
    if (!(merge_en & 0xffu))                     /* beqz -> return */
        return;
    REG_WRITE(0x3ff5c074u, REG_READ(0x3ff5c074u) & ~0x2000u);  /* 0xffffdfff */
}
/* phy_close_pa phy_chip_v7.c:? @ phy_chip_v7.o size 145B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4609c, 0x3ff460a0
 * Fidelity: high - dual-lane PA power-down verified */
void phy_close_pa(bool force_close)
{
    if (!(force_close & 0xffu)) {                    /* beqz -> soft lane */
        REG_WRITE(0x3ff4609cu, REG_READ(0x3ff4609cu) | 4u);
        REG_WRITE(0x3ff4609cu, REG_READ(0x3ff4609cu) | 16u);
        REG_WRITE(0x3ff460a0u, REG_READ(0x3ff460a0u) & ~0xc00u);
        return;
    }
    REG_WRITE(0x3ff460a0u, (REG_READ(0x3ff460a0u) & ~0xc00u) | 0x800u);
    REG_WRITE(0x3ff4609cu, REG_READ(0x3ff4609cu) & ~5u);    /* movi -5 */
    REG_WRITE(0x3ff4609cu, REG_READ(0x3ff4609cu) & ~17u);   /* movi -17 */
}
/* phy_close_rf phy_chip_v7.c:? @ phy_chip_v7.o size 130B [dwarf-sig]
 * Calls: phy_enter_critical, noise_check_loop, disable_wifi_agc, esp_dport_access_reg_read, set_xpd_sar, phy_exit_critical | Data refs: g_phyFuns | MMIO: 0x3ff00024, 0x3ff48030
 * Fidelity: high - close sequence verified per disasm + relocs */
void phy_close_rf(void)
{
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    noise_check_loop(1, 1);   /* movi a11,1 lane (a11 preserved to call) */
    disable_wifi_agc();                  /* local direct call8 */
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) & ~3u);   /* movi -3 lane */
    ((void (*)(void))g_phyFuns[48])();   /* +192 lane */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(1, 1, 0);  /* +184 */
    ((void (*)(void))g_phyFuns[49])();   /* +196 lane */
    REG_WRITE(0x3ff48030u, REG_READ(0x3ff48030u) & 0x27ffffffu);
    set_xpd_sar(0);   /* movi a10,0 lane */
    phy_exit_critical_to(crit);          /* mov a10,a4 lane */
}
/* phy_dig_reg_backup phy_chip_v7.c:4575 @ phy_chip_v7.o size 801B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45104, 0x3ff45108, 0x3ff4510c, 0x3ff45110, 0x3ff5c010, 0x3ff5c014, 0x3ff5c018, 0x3ff5c01c, 0x3ff5c02c, 0x3ff5c044, 0x3ff5c074, 0x3ff5c0cc, 0x3ff5c108, 0x3ff5c11c, 0x3ff5c124, 0x3ff5c860, 0x3ff5c87c, 0x3ff5cc0c, 0x3ff5cd04, 0x3ff5cd08, 0x3ff5cd0c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint8 phy_dig_reg_backup(bool backup_en, uint32 * mem_addr)
{
    (void)backup_en;
    (void)mem_addr;
    /* DWARF locals: uint8 i@l4577 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <phy_dig_reg_backup> (334 insns) + DWARF line rows for phy_chip_v7.c:4575.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* phy_disable_low_rate phy_chip_v7.c:? @ phy_chip_v7.o size 86B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3, write_txrate_power_offset | Data refs: (flag byte via literal) | MMIO: 0x3ff5c860, 0x3ff5c87c
 * Fidelity: high - flag + 3-lane program verified */
void phy_disable_low_rate(void)
{
    extern U8 low_rate_flag;   /* s8i target; exact symbol TODO */
    low_rate_flag = 0;
    REG_WRITE(0x3ff5c860u, REG_READ(0x3ff5c860u) & ~0x400u);
    REG_WRITE(0x3ff5c860u, (REG_READ(0x3ff5c860u) & ~0x800u) | 0x800u);
    REG_WRITE(0x3ff5c87cu, REG_READ(0x3ff5c87cu) & ~0x400u);
    write_txrate_power_offset(1);
}
/* phy_enable_low_rate phy_chip_v7.c:? @ phy_chip_v7.o size 86B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3, write_txrate_power_offset | Data refs: (flag byte via literal) | MMIO: 0x3ff5c860, 0x3ff5c87c
 * Fidelity: high - flag + 3-lane program verified */
void phy_enable_low_rate(void)
{
    extern U8 low_rate_flag;   /* s8i target; exact symbol TODO */
    low_rate_flag = 1;
    REG_WRITE(0x3ff5c860u, REG_READ(0x3ff5c860u) | 0x400u);
    REG_WRITE(0x3ff5c860u, (REG_READ(0x3ff5c860u) & ~0x800u) | 0x800u);
    REG_WRITE(0x3ff5c87cu, REG_READ(0x3ff5c87cu) & 0x800u);
    write_txrate_power_offset(1);
}
/* phy_get_adc_rand phy_chip_v7.c:? @ phy_chip_v7.o size 358B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x4, (indirect) g_phyFuns[16,42,48,55,52,46,83] | Data refs: g_phyFuns | MMIO: 0x3ff48030, 0x3ff460a0, 0x3ff66000
 * Fidelity: medium-low - stage/RMW/hook backbone verified; lane convergence TODO */
void phy_get_adc_rand(bool start_flag)
{
    sint16 rx_dc_comp[8]; (void)rx_dc_comp;   /* DWARF l4480 */
    /* Stage l16 table (4 entries, reordered) to stack. */
    REG_WRITE(0x3ff460a0u, REG_READ(0x3ff48030u));  /* cross-reg lane */
    if (!(start_flag & 0xffu)) {                   /* beqz -> 141 lane */
        ((void (*)(uint32))g_phyFuns[16])(1);      /* +64 lane */
        /* TODO: 141-lane RMWs, rejoins main flow. */
    }
    REG_WRITE(0x3ff48030u, REG_READ(0x3ff48030u) | 0xf8000000u);
    REG_WRITE(0x3ff460a0u, REG_READ(0x3ff460a0u) | 0x1000000u);
    REG_WRITE(0x3ff66000u, REG_READ(0x3ff66000u) | 0x400u);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (103, 1, 1, 7, 7, 0);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (103, 1, 2, 7, 7, 0);
    ((void (*)(void))g_phyFuns[48])();             /* +192 */
    ((void (*)(void *))g_phyFuns[55])(rx_dc_comp); /* +220 stack image */
    ((void (*)(uint32))g_phyFuns[52])(0);          /* +208 */
    ((void (*)(uint32, uint32, uint32))g_phyFuns[46])(0, 1, 10);  /* +184 */
    ((void (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[83])
        (0xfa0, 0, 10, 0, 0);                      /* +0x150; TODO exact */
}
/* phy_get_cca phy_chip_v7.c:? @ phy_chip_v7.o size 17B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c01c
 * Fidelity: high - single masked read verified */
sint8 phy_get_cca(void)
{
    return (sint8)(REG_READ(0x3ff5c01cu) & 0xffu);   /* extui 0,8 */
}
/* phy_get_cca_cnt phy_chip_v7.c:? @ phy_chip_v7.o size 56B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d05c, 0x3ff5d060
 * Fidelity: high - counter snapshot pair + busy-bit return verified */
bool phy_get_cca_cnt(uint32 * cca_cnt)
{
    cca_cnt[0] = REG_READ(0x3ff5d05cu) & 0x7ffffffu;
    cca_cnt[1] = REG_READ(0x3ff5d060u) & 0x7ffffffu;
    return (REG_READ(0x3ff5d05cu) & 0x8000000u) ? 1 : 0;  /* extui 27,5 */
}
/* phy_get_most_tpw phy_chip_v7.c:? @ phy_chip_v7.o size 32B [dwarf-sig]
 * Calls: (none) | Data refs: (two flag bytes via literals) | MMIO: (none)
 * Fidelity: high - flag-gated select verified; flag symbols TODO */
s8 phy_get_most_tpw(void)
{
    extern U8 most_tpw_sel, most_tpw_val;   /* l8ui lanes; exact symbols TODO */
    uint8 v = most_tpw_val;                 /* l8ui +14 lane */
    if (most_tpw_sel == 1)
        return (s8)v;                       /* beqi -> full return */
    return (s8)(v & 0xffu);                 /* extui lane (identical value) */
}
/* phy_get_noise_floor phy_chip_v7.c:? @ phy_chip_v7.o size 20B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c050
 * Fidelity: high - masked read with -1024 bias verified */
sint16 phy_get_noise_floor(void)
{
    return (sint16)((REG_READ(0x3ff5c050u) & 0x3ffu) - 1024);  /* extui 0,10; addmi -1024 */
}
/* phy_get_rf_cal_version phy_chip_v7.c:? @ phy_chip_v7.o size 8B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - constant return verified */
uint32 phy_get_rf_cal_version(void)
{
    return 0x12ffu;
}
/* phy_get_romfunc_addr phy_chip_v7.c:3159 @ phy_chip_v7.o size 613B [dwarf-sig]
 * Calls: phy_get_romfuncs | Data refs: g_phyFuns, phy_get_romfuncs, ram_bb_bss_bw_40_en, ram_bb_bss_cbw40_dig, ram_bb_tx_ht20_cen, ram_cbw2040_cfg, ram_check_noise_floor, ram_chip_i2c_readReg, ram_chip_i2c_writeReg, ram_dc_iq_est, ram_disable_agc, ram_en_pwdet, ram_enable_agc, ram_get_fm_sar_dout, ram_get_rf_gain_qdb, ram_index_to_txbbgain, ram_iq_est_disable, ram_iq_est_enable, ram_meas_tone_pwr_db, ram_pbus_debugmode, ram_pbus_force_mode, ram_pbus_force_test, ram_pbus_rx_dco_cal, ram_pbus_xpd_tx_on, ram_phy_get_noisefloor, ram_phy_get_vdd33, ram_read_sar_dout, ram_restart_cal, ram_rfcal_pwrctrl, ram_rfcal_txcap, ram_rfpll_reset, ram_rfpll_set_freq, ram_set_chan_cal_interp, ram_set_noise_floor, ram_set_pbus_mem, ram_set_rxclk_en, ram_set_txcap_reg, ram_set_txclk_en, ram_spur_coef_cfg, ram_start_tx_tone, ram_tx_pwctrl_bg_init, ram_txbbgain_to_index, ram_txcal_work_mode, ram_txdc_cal_v70, ram_txiq_get_mis_pwr, ram_wait_rfpll_cal_end, ram_write_gain_mem | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void phy_get_romfunc_addr(void)
{
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <phy_get_romfunc_addr> (262 insns) + DWARF line rows for phy_chip_v7.c:3159.
     * Ordered callee relocs: phy_get_romfuncs.
     */
}

/* phy_get_rssi phy_chip_v7.c:? @ phy_chip_v7.o size 48B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c050, 0x3ff5c06c
 * Fidelity: high - combined RSSI arithmetic verified */
sint16 phy_get_rssi(void)
{
    int32 a = (int32)(REG_READ(0x3ff5c050u) & 0x3ffu) - 1024;  /* addmi lane */
    int32 b = (int32)((REG_READ(0x3ff5c06cu) & 0xff00u) >> 8);
    return (sint16)((a >> 2) + b);   /* srai 2; add; sext 15 */
}
/* phy_get_rx_freq phy_chip_v7.c:? @ phy_chip_v7.o size 73B [dwarf-sig]
 * Calls: (none) | Data refs: (rodata magic pair) | MMIO: (none - fixed-point)
 * Fidelity: high - dual divide idioms verified (magic 0x2aaaaaab=/6, 0x4ec4ec4f lane) */
sint16 phy_get_rx_freq(u8 rate, u32 bb_info)
{
    uint8 r = (uint8)(rate & 0xffu);
    if (r < 8) {                             /* bgeui -> else */
        int32 x = (int16)(bb_info & 0xffffu);  /* sext 15 (low half) */
        /* signed div by 6: mulsh(0x2aaaaaab)>>3 minus sign */
        int32 q = (int32)(((int64)x * (int32)0x2aaaaaabu) >> 32);
        return (sint16)((q >> 3) - (x >> 31));
    }
    int32 y = (int16)((bb_info >> 10) & 0x3ffu);  /* extui 10,10; sext */
    if (y > 0x1ff)                           /* bge -> wrap */
        y = (int16)(y - 1024);               /* addmi -1024; sext */
    int32 z = y << 4;
    int32 q2 = (int32)(((int64)z * (int32)0x4ec4ec4fu) >> 32);
    return (sint16)((q2 >> 2) - (z >> 31));  /* srai 2; sub sign; sext */
}
/* phy_get_tx_pwr phy_chip_v7.c:? @ phy_chip_v7.o size 77B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[30], phy_printf | Data refs: g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: medium - ratio formula + diagnostic verified; hook identity TODO */
S16 phy_get_tx_pwr(void)
{
    sint16 s[8]; (void)s;   /* stack s16 array filled by hook */
    ((void (*)(void *))g_phyFuns[30])(s);   /* +0x12c lane; arg = stack */
    int16 C = (int16)(s[6] + s[7]);
    int16 A = (int16)(s[2] + s[3] - C);
    int16 D = (int16)(s[4] + s[5] - C);
    int32 q = ((int32)A << 10) / (int32)D;  /* quos lane */
    phy_printf();                           /* diagnostic; fmt via literal */
    return (S16)q;                          /* sext 15 */
}
/* phy_get_tx_rate phy_chip_v7.c:? @ phy_chip_v7.o size 17B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e060
 * Fidelity: high - single field read verified */
uint8 phy_get_tx_rate(void)
{
    return (uint8)((REG_READ(0x3ff4e060u) >> 24) & 0x7fu);   /* extui 24,7 */
}
/* phy_get_txpwr_param phy_chip_v7.c:? @ phy_chip_v7.o size 121B [dwarf-sig]
 * Calls: (none) | Data refs: chip7_sleep_params, phy_tx_pwr_error (relocs) | MMIO: (none)
 * Fidelity: high - table unpack verified per disasm + relocs */
void phy_get_txpwr_param(S8 * txpwr_backoff, S8 * txpwr_diff_flash, U16 * txpwr_ana_gain, sint8 * txpwr_dig_atten, S8 * txpwr_correct_pwr, S16 * txpwr_meas_error)
{
    extern uint8 chip7_sleep_params[];
    extern sint16 phy_tx_pwr_error;
    uint8 *tbl = &chip7_sleep_params[4];     /* +4 lane */
    for (int i = 0; i < 4; i++)              /* loop a8=4 */
        txpwr_backoff[i] = (S8)(tbl[2 * i + 4] | (tbl[2 * i + 5] << 8));  /* l16ui lane, low byte */
    txpwr_dig_atten[0] = (sint8)tbl[24 + 95];/* l8ui lane */
    txpwr_diff_flash[0] = 0;                 /* s8i lanes */
    txpwr_diff_flash[1] = 0;
    uint16 lo = (uint16)(tbl[188] | (tbl[189] << 8));
    uint16 hi = (uint16)(tbl[190] | (tbl[191] << 8));
    txpwr_ana_gain[0] = (U16)(((lo << 9) | hi) & 0xffffu);  /* slli/or lane */
    txpwr_correct_pwr[0] = (S8)tbl[184];     /* l8ui lane */
    txpwr_meas_error[0] = phy_tx_pwr_error;  /* l16ui/s16i lane */
}
/* phy_i2c_check phy_chip_v7.c:? @ phy_chip_v7.o size 409B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[38] (per iter), phy_printf (per iter) | Data refs: g_phyFuns, phy_printf | MMIO: (none direct)
 * Fidelity: medium - 9 scan loops with exact (host,count) verified; printf args TODO */
void phy_i2c_check(void)
{
    /* Diagnostic I2C scan: per host, read via word-38 hook + print. */
    static const struct { uint8 host, aux, n; } scans[] = {
        {106, 2, 10}, {103, 1, 16}, {102, 4, 13}, {107, 2, 12}, {100, 0, 11},
        {98, 0, 12}, {99, 0, 6}, {101, 4, 7}, {104, 3, 3}, {109, 3, 10},
    };
    for (unsigned s = 0; s < 10; s++) {
        for (int i = 0; i < scans[s].n; i++) {
            ((void (*)(uint32, uint32, uint32))g_phyFuns[38])
                (scans[s].host, scans[s].aux, 0);
            phy_printf();                /* per-iter diagnostic */
        }
    }
}
/* phy_init_param_set phy_chip_v7.c:? @ phy_chip_v7.o size 17B [dwarf-sig]
 * Calls: (none) | Data refs: (flag byte via literal) | MMIO: (none)
 * Fidelity: high - masked flag store verified */
void phy_init_param_set(uint8 param)
{
    extern U8 init_param_flag;   /* s8i target; exact symbol TODO */
    init_param_flag = (uint8)(param & 1u);   /* extui 0,1 lane */
}
/* phy_init_pwr_print phy_chip_v7.c:? @ phy_chip_v7.o size 218B [dwarf-sig]
 * Calls: phy_printf x~8 | Data refs: chip7_sleep_params, phy_printf, tx_rf_ana_gain | MMIO: (none)
 * Fidelity: low - diagnostic dump; call/loop skeleton only, format/table mapping TODO */
void phy_init_pwr_print(void)
{
    /* TODO(ground-truth): ~8 phy_printf calls dumping init power tables
     * (l16ui walks over sleep_params/tx_rf_ana_gain with bne-bounded loops).
     * Reconstruct formats from .rodata.str1.4 literals in rdis. */
    phy_printf();
}
/* phy_param_set phy_chip_v7.c:? @ phy_chip_v7.o size 71B [dwarf-sig]
 * Calls: (none) | Data refs: (two flag bytes via literals) | MMIO: (none)
 * Fidelity: high - mode-selected constant pairs verified */
void phy_param_set(uint8 mode_set)
{
    extern U8 param_flag_a, param_flag_b;   /* s8i targets; exact symbols TODO */
    if (!(mode_set & 0xffu)) {                       /* bnez -> else */
        param_flag_a = 95;
        param_flag_b = (uint8)-61;
    } else {
        param_flag_a = 75;
        param_flag_b = (uint8)-106;
    }
}
/* phy_reg_check phy_chip_v7.c:? @ phy_chip_v7.o size 473B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf (per word) | Data refs: esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff00000, 0x3ff46000, 0x3ff48000, 0x3ff48800, 0x3ff66000 (+more)
 * Fidelity: medium-low - region dump loops verified; region list TODO (see rdis) */
void phy_reg_check(void)
{
    uint16 i; (void)i;   /* DWARF l4857 */
    /* Diagnostic register dump: per region (base,count): read + print
     * each word. Regions seen: (0x3ff48000,216), (0x3ff48800,164),
     * (0x3ff66000,60), (0x3ff00000,0x5bc), (0x3ff46000,252), ... */
    static const struct { uint32 base; uint32 n; } regions[] = {
        {0x3ff48000u, 216}, {0x3ff48800u, 164}, {0x3ff66000u, 60},
        {0x3ff00000u, 0x5bc}, {0x3ff46000u, 252},
    };
    for (unsigned r = 0; r < 5; r++) {
        for (uint32 k = 0; k < regions[r].n; k += 4) {
            uint32 v = REG_READ(regions[r].base + k);
            (void)v;
            phy_printf();   /* TODO: fmt/args */
        }
    }
}
/* phy_reg_init phy_chip_v7.c:? @ phy_chip_v7.o size 199B [dwarf-sig]
 * Calls: tx_paon_set, bb_reg_init, agc_reg_init, esp_dport_access_reg_read, mac_enable_bb, phy_set_bbfreq_init, rx_11b_opt | Data refs: (static halfwords via literals) | MMIO: 0x3ff5c030, 0x3ff5c11c, 0x3ff5c120, 0x3ff5d03c, 0x3ff5d040
 * Fidelity: medium - init order + constant programs verified; static symbols TODO */
void phy_reg_init(void)
{
    extern sint16 reg_init_tbl[];   /* l16ui +188/+190 source */
    extern sint16 reg_init_dst[2];    /* s16i destination */
    reg_init_dst[0] = reg_init_tbl[94];            /* +188 lane */
    reg_init_dst[1] = reg_init_tbl[95];            /* +190 lane */
    tx_paon_set();
    bb_reg_init();
    agc_reg_init();
    REG_WRITE(0x3ff5d040u, REG_READ(0x3ff5d040u) | 0x80000000u);
    REG_WRITE(0x3ff5d03cu, 0x401800aau);
    mac_enable_bb();
    phy_set_bbfreq_init(1);                        /* movi a10,1 lane */
    ((void (*)(void))g_phyFuns[105])();            /* +0x1a4 lane */
    ((void (*)(void))g_phyFuns[30])();             /* +120 lane */
    REG_WRITE(0x3ff5c030u, (REG_READ(0x3ff5c030u) & 0xfffc07ffu) | 0x1a000u);
    REG_WRITE(0x3ff5c11cu, 0xe000u);
    REG_WRITE(0x3ff5c120u, 0x1e101e1cu);
    opt_11b_resart();
    rx_11b_opt(1);                                 /* movi a10,1 lane */
}
/* phy_rfcal_data_check phy_chip_v7.c:? @ phy_chip_v7.o size 199B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none - checksum)
 * Fidelity: medium - header/checksum/compare/store verified; no-check return lane has no value setup (TODO) */
bool phy_rfcal_data_check(bool check_flag, uint8 * rf_cal_data, uint8 * init_param)
{
    rf_cal_data[0] = 0xffu;                  /* s8i -1 lane */
    rf_cal_data[1] = 18;
    rf_cal_data[2] = 0;
    rf_cal_data[3] = 0;
    uint32 sum = 0;
    for (int i = 0; i < 0x15a; i++)          /* loop a12=0x15a */
        sum += phy_byte_to_word(rf_cal_data + 4 * i);
    for (int i = 0; i < 32; i++)             /* loop a11=32 */
        sum += phy_byte_to_word(init_param + 4 * i);
    uint32 check = ~sum;                     /* xor -1 lane */
    uint32 stored = phy_byte_to_word(rf_cal_data + 104);
    if (!(check_flag & 0xffu)) {             /* beqz -> store lane */
        rf_cal_data[104] = (uint8)check;
        rf_cal_data[105] = (uint8)(check >> 8);
        rf_cal_data[106] = (uint8)(check >> 16);
        rf_cal_data[107] = (uint8)(check >> 24);
        /* NOTE: no return-value setup on this lane in disasm (fallthrough
         * residue); callers must not rely on it. Kept as bare return. */
        return;
    }
    return (sum - stored) != 0;              /* sub/movnez lane */
}
/* phy_rfcal_data_check_value phy_chip_v7.c:3813 @ phy_chip_v7.o size 759B [dwarf-sig]
 * Calls: memcpy | Data refs: chip7_sleep_params, g_phyFuns, memcpy | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 phy_rfcal_data_check_value(uint8 * rf_cal_data, sleep_param_t * cal_param, bool check_en)
{
    (void)rf_cal_data;
    (void)cal_param;
    (void)check_en;
    /* DWARF locals: uint16 i@l3815, uint16 j@l3815, sint8[] iq_out_old@l3816, sint8[] iq_out@l3816, uint16 check_flag@l3817 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <phy_rfcal_data_check_value> (280 insns) + DWARF line rows for phy_chip_v7.c:3813.
     * Ordered callee relocs: memcpy.
     */
}

/* phy_rx11blr_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 97B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c860, 0x3ff5c87c
 * Fidelity: high - triple field program verified */
void phy_rx11blr_cfg(uint8 en)
{
    uint8 e = (uint8)(en & 0xffu);
    REG_WRITE(0x3ff5c860u, (REG_READ(0x3ff5c860u) & 0xfffffbffu) | (((uint32)e << 10) & 0x400u));
    REG_WRITE(0x3ff5c860u, (REG_READ(0x3ff5c860u) & 0xfffff7ffu) | (((uint32)e << 11) & 0x800u));
    REG_WRITE(0x3ff5c87cu, (REG_READ(0x3ff5c87cu) & 0xfffff7ffu) | (((uint32)e << 11) & 0x800u));
}
/* phy_rx_sense_set phy_chip_v7.c:? @ phy_chip_v7.o size 128B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c010, 0x3ff5c014, 0x3ff5c044
 * Fidelity: high - triple threshold program verified */
void phy_rx_sense_set(uint8 sense_thr)
{
    uint8 t = (uint8)(sense_thr & 0xffu);
    REG_WRITE(0x3ff5c010u, (REG_READ(0x3ff5c010u) & 0x7fffffu) | ((uint32)t << 23));
    REG_WRITE(0x3ff5c014u, (REG_READ(0x3ff5c014u) & 0x7fffffu) | ((uint32)t << 23));
    REG_WRITE(0x3ff5c044u, (REG_READ(0x3ff5c044u) & 0xffffff00u) | t);
    if (t == 0)                                      /* bnez -> else */
        REG_WRITE(0x3ff5c108u, REG_READ(0x3ff5c108u) | 0x200u);
    else
        REG_WRITE(0x3ff5c108u, REG_READ(0x3ff5c108u) & ~0x200u);  /* 0xfffffdff */
}
/* phy_set_cca_cnt phy_chip_v7.c:? @ phy_chip_v7.o size 62B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5d058
 * Fidelity: high - max program + optional start-bit verified */
void phy_set_cca_cnt(uint32 cnt_max, bool clr)
{
    REG_WRITE(0x3ff5d058u, (REG_READ(0x3ff5d058u) & 0xf8000000u) |
                           (cnt_max & 0x7ffffffu));
    if (clr & 0xffu)                                 /* beqz -> skip */
        REG_WRITE(0x3ff5d058u, REG_READ(0x3ff5d058u) | 0x18000000u);
}
/* phy_set_most_tpw phy_chip_v7.c:? @ phy_chip_v7.o size 61B [dwarf-sig]
 * Calls: set_most_pwr_reg, set_chan_dig_gain | Data refs: (flag bytes via literals) | MMIO: (none)
 * Fidelity: medium - store/call/store sequence verified; flag symbols + set_most_pwr_reg return use TODO */
void phy_set_most_tpw(s8 most_target_power)
{
    extern U8 most_tpw_flag0, most_tpw_flag1, most_tpw_flag2;  /* s8i lanes */
    most_tpw_flag0 = (uint8)most_target_power;   /* s8i a2 lane */
    uint8 r = set_most_pwr_reg();                /* u8 return per DWARF */
    most_tpw_flag1 = r;                          /* s8i a10 lane */
    extern uint8 sleep_byte81_b;                 /* l8ui +81 -> a10 lane */
    /* NOTE: sleep_byte81_b is moved to a10 pre-call though DWARF says
     * set_chan_dig_gain is void(void); true arity TODO. */
    (void)sleep_byte81_b;
    set_chan_dig_gain();
    most_tpw_flag2 = 1;                          /* s8i lane */
}
/* phy_set_rfrx_dcap phy_chip_v7.c:? @ phy_chip_v7.o size 220B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[41] x2+, g_phyFuns[42] x2+, set_chan_rxcomp | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium-low - enable gate, w41/w42 hook families, rxcomp(-28) tail, flag set verified; exact lane convergence TODO (see rdis) */
void phy_set_rfrx_dcap(bool enable)
{
    extern U8 rfrx_dcap_flag;   /* l8ui gate/s8i lanes; exact symbol TODO */
    if (rfrx_dcap_flag == 0 && (enable & 0xffu) == 1) {
        ((void (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[41])(100, 0, 7, 3, 0);
        ((void (*)(uint32, uint32, uint32, uint32, uint32))g_phyFuns[41])(100, 0, 4, 3, 0);
    } else {
        ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])(100, 0, 4, 3, 0, 0);
    }
    /* Common tail (lane convergence approximate): w42 refresh pair. */
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])(100, 0, 7, 3, 0, 0);
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])(100, 0, 4, 3, 0, 0);
    set_chan_rxcomp(-28);                        /* movi -28 lane */
    rfrx_dcap_flag = 1;
}
/* phy_version_print phy_chip_v7.c:? @ phy_chip_v7.o size 27B [dwarf-sig]
 * Calls: phy_printf | Data refs: phy_printf | MMIO: (none)
 * Fidelity: medium - call + 0x12ff version lane verified; fmt/arg symbols TODO */
void phy_version_print(void)
{
    extern const char ver_fmt2[];   /* 0xd4 lane; exact symbol TODO */
    extern int ver2_a, ver2_b, ver2_c;  /* 0xe0/0xec/0xf4 lanes; TODO */
    phy_printf();   /* TODO: args (fmt, a, b, 0x12ff, c) by analogy with get_phy_version_str */
    (void)ver_fmt2; (void)ver2_a; (void)ver2_b; (void)ver2_c;
}
/* phy_wakeup_init phy_chip_v7.c:? @ phy_chip_v7.o size 198B [dwarf-sig]
 * Calls: phy_enter_critical, phy_dis_hw_set_freq, i2c_master_reset, reg_init_begin, phy_i2c_init, phy_reg_init, set_chan_reg, enable_wifi_agc, phy_en_hw_set_freq, phy_exit_critical | Data refs: (flag bytes via literals) | MMIO: 0x3ff460a0, 0x3ff5c080
 * Fidelity: medium - wake sequence verified; flag symbols TODO */
void phy_wakeup_init(void)
{
    extern U8 wu_flag_a, wu_flag_b, wu_flag_c;   /* exact symbols TODO */
    extern CriticalType phy_enter_critical_ret(void);
    extern void phy_exit_critical_to(CriticalType);
    CriticalType crit = phy_enter_critical_ret();
    wu_flag_a = 1;                               /* s8i lanes */
    wu_flag_b = 1;
    REG_WRITE(0x3ff460a0u, (REG_READ(0x3ff460a0u) & 0xfffff0ffu) | 0xa00u);
    phy_dis_hw_set_freq();
    i2c_master_reset();
    reg_init_begin(1);                           /* movi a10,1 lane */
    phy_i2c_init();
    phy_reg_init();
    set_chan_reg();
    REG_WRITE(0x3ff460a0u, REG_READ(0x3ff460a0u) & 0xfffff0ffu);
    ((void (*)(uint32, uint32, uint32))g_phyFuns[38])(99, 0, 0);  /* +152 */
    enable_wifi_agc();
    wu_flag_a = 0;
    wu_flag_b = 0;
    phy_en_hw_set_freq();
    if (wu_flag_c)                               /* l8ui gate */
        REG_WRITE(0x3ff5c080u, REG_READ(0x3ff5c080u) | 192u);
    phy_exit_critical_to(crit);                  /* mov a10,a6 lane */
}
/* phy_wifi_bb_reset phy_chip_v7.c:5109 @ phy_chip_v7.o size 38B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff00024
 * Fidelity: high - pulse-bit sequence fully verified per disasm */
void phy_wifi_bb_reset(void)
{
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) | 1u);
    ets_delay_us(1);
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) & ~1u);  /* movi -2 and-lane */
}
/* phy_wifi_enable_set phy_chip_v7.c:? @ phy_chip_v7.o size 61B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c080
 * Fidelity: high - dual-lane bit set/clear verified */
void phy_wifi_enable_set(uint8 enable)
{
    if (enable & 0xffu)                              /* beqz -> clear lane */
        REG_WRITE(0x3ff5c080u, REG_READ(0x3ff5c080u) & ~193u);  /* -193 */
    else
        REG_WRITE(0x3ff5c080u, REG_READ(0x3ff5c080u) | 192u);
}
/* phy_wifitx_low_power phy_chip_v7.c:? @ phy_chip_v7.o size 331B [dwarf-sig]
 * Calls: set_tx_gain_table, tx_gain_table_set | Data refs: (gain tables via literals) | MMIO: 0x3ff46004, 0x3ff46008
 * Fidelity: medium-low - clamp lanes, table walk, gain commit verified; walk arithmetic + commit values TODO */
void phy_wifitx_low_power(bool force_en, uint8 level, sint8 gain_atten)
{
    uint8 lv = (uint8)(level & 0xffu);
    int8 ga = (int8)gain_atten;                  /* sext 7 */
    (void)ga;
    if (!(force_en & 0xffu)) {                   /* beqz -> 155 lane */
        extern U8 wifitx_lp_flag;                /* s8i target */
        wifitx_lp_flag = 0;
        return;
    }
    if (lv > 10)                                 /* bltu 10 -> d5 lane */
        lv = 11;
    /* Clamp atten to [-5,7): < -5 -> 251; >= 7 -> 6 (bgei/blt lanes). */
    /* Table walk (muluh /6 divide, bit-loop accumulate into pa/bb), then
     * set_tx_gain_table(pa, bb), 8-tap adjust loop (sub lanes), flag
     * stores, MMIO pair 0x3ff46004/0x3ff46008 from stack words,
     * tx_gain_table_set(). TODO: exact values from rdis. */
    set_tx_gain_table(0, 0);                     /* TODO exact pa/bb */
    tx_gain_table_set();                         /* presumed void(void) */
}
/* ram_bb_bss_bw_40_en phy_chip_v7.c:? @ phy_chip_v7.o size 34B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff00024
 * Fidelity: high - gated RMW verified */
void ram_bb_bss_bw_40_en(int bb_ht_2040)
{
    if (!bb_ht_2040)                             /* beqz -> return */
        return;
    REG_WRITE(0x3ff00024u, (REG_READ(0x3ff00024u) & ~13u) | 4u);
}
/* ram_bb_bss_cbw40_dig phy_chip_v7.c:? @ phy_chip_v7.o size 35B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff00024
 * Fidelity: high - bit2 RMW verified */
void ram_bb_bss_cbw40_dig(int cbw40)
{
    REG_WRITE(0x3ff00024u, (REG_READ(0x3ff00024u) & ~13u) | (((uint32)(cbw40 & 1u)) << 2));
}
/* ram_bb_tx_ht20_cen phy_chip_v7.c:? @ phy_chip_v7.o size 36B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x60033c6c
 * Fidelity: high - bit27 RMW verified */
void ram_bb_tx_ht20_cen(int tx_ht20_cen_en)
{
    REG_WRITE(0x60033c6cu, (REG_READ(0x60033c6cu) & 0xf7ffffffu) |
                           (((uint32)(tx_ht20_cen_en & 1u)) << 27));
}
/* ram_cbw2040_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 105B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x4 | Data refs: esp_dport_access_reg_read | MMIO: 0x60033c6c, 0x3ff5d000
 * Fidelity: high - dual-lane bit set/clear verified */
void ram_cbw2040_cfg(bool cbw20_sel)
{
    if (cbw20_sel & 0xffu) {                         /* beqz -> clear lane */
        REG_WRITE(0x60033c6cu, REG_READ(0x60033c6cu) | 0x8000000u);
        REG_WRITE(0x3ff5d000u, REG_READ(0x3ff5d000u) | 64u);
    } else {
        REG_WRITE(0x60033c6cu, REG_READ(0x60033c6cu) & ~0x8000000u);
        REG_WRITE(0x3ff5d000u, REG_READ(0x3ff5d000u) & ~65u);  /* -65 */
    }
}
/* ram_check_noise_floor phy_chip_v7.c:? @ phy_chip_v7.o size 234B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x5 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c018, 0x3ff5c050, 0x60033c00
 * Fidelity: medium - program + bounded poll + biased read verified; poll-lane plumbing approximate */
sint16 ram_check_noise_floor(void)
{
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) & ~0x800000u);
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) | 0x2000000u);
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) & ~0x2000000u);
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) | 0x800000u);
    /* Timer-bounded poll (0x60033c00, 10000 ticks); timeout flag -> negate. */
    uint8 timeout = 0;                       /* a7 lane */
    uint32 t0 = REG_READ(0x60033c00u);
    while ((REG_READ(0x60033c00u) - t0) < 10000u) {  /* approximate bound */
        uint32 st = REG_READ(0x3ff5c018u);
        if (((st >> 24) & 0xffu) != 0)       /* extui 24,8 gate */
            break;
        if (timeout)                         /* beqz a7 lanes */
            break;
    }
    int16 v = (int16)(((REG_READ(0x3ff5c050u) & 0x3ffu) - 1024) & 0xffff);
    sint16 ret;
    if (v >= -351)
        ret = timeout ? 352 : -352;          /* 0x160/timeout lanes */
    else
        ret = (v < -360) ? -360 : v;
    return timeout ? (sint16)(-ret) : ret;   /* neg lane */
}
/* ram_disable_agc phy_chip_v7.c:? @ phy_chip_v7.o size 27B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c030
 * Fidelity: high - set-bit RMW verified */
void ram_disable_agc(void)
{
    REG_WRITE(0x3ff5c030u, REG_READ(0x3ff5c030u) | 0x100u);
}
/* ram_enable_agc phy_chip_v7.c:? @ phy_chip_v7.o size 27B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c030
 * Fidelity: high - clear-bit RMW verified */
void ram_enable_agc(void)
{
    REG_WRITE(0x3ff5c030u, REG_READ(0x3ff5c030u) & ~0x100u);  /* 0xfffffeff */
}
/* ram_gen_rx_gain_table phy_chip_v7.c:? @ phy_chip_v7.o size 351B [dwarf-sig]
 * Calls: memcpy, phy_printf x2 | Data refs: memcpy, phy_printf | MMIO: (none)
 * Fidelity: medium-low - memcpy staging, /6 scaling, sweep loop, diagnostics verified; pack arithmetic TODO */
uint8 ram_gen_rx_gain_table(uint32 * rx_gain_table, uint8 gain_lpf_max, uint8 * rx_gain_swp, sint8 * rx_gain_swp_step, uint8 rx_gain_swp_num)
{
    sint8 gain_index; (void)gain_index;           /* DWARF l163 */
    const sint8 gain_lpf_step = 0; (void)gain_lpf_step;  /* DWARF l165 */
    uint8 swp_cnt = 0;                           /* DWARF l167 */
    uint8 rx_gain_swp_index = 0; (void)rx_gain_swp_index;  /* DWARF l168 */
    uint8 phy_rx_gain_max = gain_lpf_max; (void)phy_rx_gain_max;  /* DWARF l169 */
    uint16 bb_coarse_gain[8]; (void)bb_coarse_gain;  /* DWARF l170 */
    uint16 gain_lpf_set, gain_lpf_fine_set; (void)gain_lpf_set; (void)gain_lpf_fine_set;
    uint16 gain_set; (void)gain_set;             /* DWARF l173 */
    uint16 bbc_i; (void)bbc_i;
    (void)rx_gain_table; (void)rx_gain_swp; (void)rx_gain_swp_step; (void)rx_gain_swp_num;
    /* memcpy staging, fixed-point /6 scaling (0x2aaaaaab), sweep loop over
     * rx_gain_swp entries with step adds, table fill, printf diagnostics,
     * return swp count/max. TODO: exact pack from rdis. */
    memcpy(bb_coarse_gain, rx_gain_swp, 8);
    for (swp_cnt = 0; ; swp_cnt++) {             /* bounded sweep; TODO bound */
        phy_printf();
        if (swp_cnt >= rx_gain_swp_num)
            break;
    }
    return swp_cnt;
}
/* ram_phy_get_noisefloor phy_chip_v7.c:? @ phy_chip_v7.o size 62B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c050, 0x3ff5d050
 * Fidelity: high - biased read, low clamp, status-bit set verified */
sint16 ram_phy_get_noisefloor(void)
{
    int16 v = (int16)(((REG_READ(0x3ff5c050u) & 0x3ffu) - 1024) & 0xffff);  /* sext */
    sint16 ret;
    if (v >= -351)                               /* bge -351 */
        ret = -352;                              /* movi -352 lane */
    else
        ret = (v < -360) ? -360 : v;             /* max -360 lane */
    REG_WRITE(0x3ff5d050u, REG_READ(0x3ff5d050u) | 1u);
    return ret;
}
/* ram_set_noise_floor phy_chip_v7.c:? @ phy_chip_v7.o size 98B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2, set_rx_sense (gated) | Data refs: (flag bytes via literals) | MMIO: 0x3ff5c018
 * Fidelity: medium - clamp + program + gated sense call verified; flag symbols TODO */
void ram_set_noise_floor(sint16 noise)
{
    extern U8 nf_gate_flag, nf_sense_flag;   /* l8ui lanes; exact symbols TODO */
    int16 n = (int16)noise;                  /* sext 15 */
    uint32 fld;
    if (n >= -351)                           /* bge -351 */
        fld = 0x5400u;                       /* l32r lane */
    else
        fld = (uint32)(((n < -360 ? -360 : n) & 0x3ffu) << 5);  /* max/clamp */
    REG_WRITE(0x3ff5c018u, (REG_READ(0x3ff5c018u) & 0xffff801fu) | fld);
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) | 16u);
    if (nf_gate_flag)                        /* beqz -> return */
        set_rx_sense((int8)nf_sense_flag);   /* sext lane */
}
/* ram_set_pbus_mem phy_chip_v7.c:844 @ phy_chip_v7.o size 675B [dwarf-sig]
 * Calls: memcpy, esp_dport_access_reg_read | Data refs: .rodata, .rodata.ram_set_pbus_mem, esp_dport_access_reg_read, memcpy | MMIO: 0x3ff45034, 0x3ff45038, 0x3ff46030, 0x3ff46034, 0x3ff46038, 0x3ff4603c, 0x3ff46040, 0x3ff46044
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_set_pbus_mem(void)
{
    /* DWARF locals: unsigned int i@l851, unsigned int j@l851, unsigned int index_start@l852, unsigned int index_end@l852, bool bt_mode_wifibb@l855, unsigned int[] table_rxon@l858, unsigned int[] table_rxoff@l862, unsigned int[] table_txon@l865, unsigned int[] table_txoff@l870, unsigned int[] table_paon@l873, unsigned int[] table_paoff@l875, unsigned int[] table_rxon_bt@l878, unsigned int[] table_rxoff_bt@l882, unsigned int[] table_txon_bt@l885, unsigned int[] table_txoff_bt@l890, u32 addr@l902 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <ram_set_pbus_mem> (266 insns) + DWARF line rows for phy_chip_v7.c:844.
     * Ordered callee relocs: memcpy, esp_dport_access_reg_read.
     */
}

/* ram_set_rxclk_en phy_chip_v7.c:? @ phy_chip_v7.o size 41B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff460a0
 * Fidelity: high - moveqz-gated field verified */
void ram_set_rxclk_en(bool rxclk_en)
{
    /* a10 = en ? 0xc000 : 0 (moveqz a10,0,a2 lane). */
    uint32 v = (rxclk_en & 0xffu) ? 0xc000u : 0u;
    REG_WRITE(0x3ff460a0u, (REG_READ(0x3ff460a0u) & 0xffff3fffu) | v);
}
/* ram_set_txclk_en phy_chip_v7.c:? @ phy_chip_v7.o size 41B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff460a0
 * Fidelity: high - moveqz-gated field verified */
void ram_set_txclk_en(bool txclk_en)
{
    uint32 v = (txclk_en & 0xffu) ? 0x30000u : 0u;
    REG_WRITE(0x3ff460a0u, (REG_READ(0x3ff460a0u) & 0xfffcffffu) | v);
}
/* ram_spur_coef_cfg phy_chip_v7.c:1934 @ phy_chip_v7.o size 486B [dwarf-sig]
 * Calls: rtc_get_xtal, esp_dport_access_reg_read, .text.spur_cal$part$8 | Data refs: (none) | MMIO: 0x3ff5cc48, 0x3ff5d014, 0x3ff5d018, 0x3ff5d01c, 0x3ff5d020
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int ram_spur_coef_cfg(int8 channel, uint16 freq, int8 sub_chan_cfg)
{
    (void)channel;
    (void)freq;
    (void)sub_chan_cfg;
    /* DWARF locals: int i@l1936, int data1@l1936, int data2@l1936, int[] fspur@l1937, int freq_base@l1938, uint8[] fspur_chan_en@l1939, uint8[] fspur_total_en@l1939, int[] coef@l1940, int BW_h@l1942 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <ram_spur_coef_cfg> (175 insns) + DWARF line rows for phy_chip_v7.c:1934.
     * Ordered callee relocs: rtc_get_xtal, esp_dport_access_reg_read, .text.spur_cal$part$8.
     */
}

/* ram_start_tx_tone phy_chip_v7.c:? @ phy_chip_v7.o size 118B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, (indirect) table+68 | Data refs: (table via literal) | MMIO: 0x3ff460b8
 * Fidelity: medium - MHz-to-reg div-by-5 lanes + hook call verified; hook args partially stale (TODO) */
void ram_start_tx_tone(int tone1_en, int freq_1_mhz, int tone1_atten, int tone2_en, int freq_2_mhz, int tone2_atten)
{
    unsigned int reg_freq_1, reg_freq_2;   /* DWARF l1574-5 */
    int cw_gen_sel; (void)cw_gen_sel;      /* DWARF l1580 */
    /* reg = ((freq<<s)*0x66666667>>32>>1 - sign) & mask: signed /5.
     * s=7,mask=0xfff when bit29 clear else s=5,mask=0x3ff. */
    uint32 mode = REG_READ(0x3ff460b8u);
    unsigned sh = (mode & 0x20000000u) ? 5 : 7;
    unsigned mk = (mode & 0x20000000u) ? 0x3ffu : 0xfffu;
    int32 f1 = freq_1_mhz, f2 = freq_2_mhz;
    int32 q1 = (int32)(((int64)(f1 << sh) * (int32)0x66666667ll >> 32) >> 1) - (f1 >> 31);
    int32 q2 = (int32)(((int64)(f2 << sh) * (int32)0x66666667ll >> 32) >> 1) - (f2 >> 31);
    reg_freq_1 = (unsigned)(q1 & mk);
    reg_freq_2 = (unsigned)(q2 & mk);
    /* hook word 17 (+68): a11/a14 carry reg_freq_1/2 (untouched since
     * computation); full arg set verified. Table symbol TODO (likely g). */
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[17])(
        (uint32)(tone1_en & 0xff), reg_freq_1, (uint32)(tone1_atten & 0xff),
        (uint32)(tone2_en & 0xff), reg_freq_2, (uint32)(tone2_atten & 0xff));
}
/* ram_write_gain_mem phy_chip_v7.c:? @ phy_chip_v7.o size 97B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45034, 0x3ff45038
 * Fidelity: high - word-pair program + mask lanes verified */
void ram_write_gain_mem(u32 data_h, u32 data_l, u8 addr)
{
    uint8 a = (uint8)(addr & 0xffu);
    REG_WRITE(0x3ff45038u, data_l);              /* s32i a3 lane */
    REG_WRITE(0x3ff45034u, (REG_READ(0x3ff45034u) & 0xfffc0000u) |
                           ((((uint32)a) << 8) + 0x1000fu));
    REG_WRITE(0x3ff45038u, data_h);              /* s32i a2 lane */
    REG_WRITE(0x3ff45034u, REG_READ(0x3ff45034u) & 0xfffcffffu);
}
/* read_hw_noisefloor phy_chip_v7.c:? @ phy_chip_v7.o size 20B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c018
 * Fidelity: high - field read with -1024 bias verified */
sint16 read_hw_noisefloor(void)
{
    return (sint16)(((REG_READ(0x3ff5c018u) >> 5) & 0x3ffu) - 1024);  /* extui 5,10; addmi */
}
/* reg_init_begin phy_chip_v7.c:? @ phy_chip_v7.o size 92B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[40], esp_dport_access_reg_read, fe_reg_init, i2cmst_reg_init | Data refs: g_phyFuns | MMIO: 0x3ff48030, 0x3ff66000
 * Fidelity: high - write + RMW pair + gated init pair verified */
void reg_init_begin(bool wakeup)
{
    ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[40])(102, 4, 12, 0);
    REG_WRITE(0x3ff48030u, REG_READ(0x3ff48030u) | 0xf8000000u);
    REG_WRITE(0x3ff66000u, REG_READ(0x3ff66000u) | 0x400u);
    if (!(wakeup & 0xffu)) {                       /* bnez a2 -> ret (skip) */
        fe_reg_init();
        i2cmst_reg_init();
    }
}
/* register_chipv7_phy phy_chip_v7.c:3912 @ phy_chip_v7.o size 691B [dwarf-sig]
 * Calls: phy_wakeup_init, phy_get_romfunc_addr, reset_rf_dig, phy_dis_hw_set_freq, esp_dport_access_reg_read, i2c_master_reset, phy_rfcal_data_check, phy_rfcal_data_check_value, register_chipv7_phy_init_param, rf_cal_data_recovery, write_freq_mem_all, rf_init, bb_init, rf_cal_data_backup, chip_v7_set_chan_nomac, force_txrxoff, chip_v7_set_chan_offset, tsens_code_read, phy_en_hw_set_freq, enable_wifi_agc | Data refs: bb_init, btpwr_tsen_init, btpwr_tsen_old, chip7_phy_init_ctrl, chip7_sleep_params, chip_v7_set_chan_nomac, chip_v7_set_chan_offset, enable_wifi_agc, esp_dport_access_reg_read, force_hw_set_freq_flag, force_txrxoff, g_phyFuns, i2c_master_reset, init_wifi_disable, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_get_romfunc_addr, phy_in_most_power, phy_init_flag, phy_rfcal_data_check, phy_rfcal_data_check_value, phy_wakeup_init, pwrdet_offset, re_entry, register_chipv7_phy_init_param, reset_rf_dig, rf_cal_data_backup, rf_cal_data_recovery, rf_init, tsens_code_read, write_freq_mem_all | MMIO: 0x3ff4e0c4, 0x3ff5c080, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int register_chipv7_phy(u8 * init_param, uint8 * rf_cal_data, uint8 rf_cal_level)
{
    (void)init_param;
    (void)rf_cal_data;
    (void)rf_cal_level;
    /* DWARF locals: u32 i@l3916, s8[] init_param_default@l3918, u32 t0@l3919, bool deep_sleep_wakeup@l3920, bool rf_cal_check_fail@l3921, uint8 rst_cause@l3922, sleep_param_t cal_param@l3923, uint16 data_check@l3924 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <register_chipv7_phy> (253 insns) + DWARF line rows for phy_chip_v7.c:3912.
     * Ordered callee relocs: phy_wakeup_init, phy_get_romfunc_addr, reset_rf_dig, phy_dis_hw_set_freq, esp_dport_access_reg_read, i2c_master_reset, phy_rfcal_data_check, phy_rfcal_data_check_value, register_chipv7_phy_init_param, rf_cal_data_recovery, write_freq_mem_all, rf_init, bb_init, rf_cal_data_backup, chip_v7_set_chan_nomac, force_txrxoff, chip_v7_set_chan_offset, tsens_code_read, phy_en_hw_set_freq, enable_wifi_agc.
     */
}

/* register_chipv7_phy_init_param phy_chip_v7.c:2910 @ phy_chip_v7.o size 533B [dwarf-sig]
 * Calls: rtc_get_xtal | Data refs: chip7_phy_init_ctrl, rtc_get_xtal | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int register_chipv7_phy_init_param(s8 * init_param)
{
    (void)init_param;
    /* DWARF locals: int i@l2912, int start@l2912, uint8 xtal_freq@l2913 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <register_chipv7_phy_init_param> (198 insns) + DWARF line rows for phy_chip_v7.c:2910.
     * Ordered callee relocs: rtc_get_xtal.
     */
}

/* reset_rf_dig phy_chip_v7.c:? @ phy_chip_v7.o size 118B [dwarf-sig]
 * Calls: disable_wifi_agc, esp_dport_access_reg_read, ets_delay_us, force_txrxoff | Data refs: | MMIO: 0x3ff00024, 0x3ff000d0, 0x3ff48030
 * Fidelity: high - reset dance verified per disasm */
void reset_rf_dig(void)
{
    disable_wifi_agc();
    REG_WRITE(0x3ff00024u, REG_READ(0x3ff00024u) & ~3u);   /* movi -3 */
    REG_WRITE(0x3ff000d0u, REG_READ(0x3ff000d0u) | 3u);
    ets_delay_us(1);
    REG_WRITE(0x3ff000d0u, REG_READ(0x3ff000d0u) & ~4u);
    REG_WRITE(0x3ff48030u, REG_READ(0x3ff48030u) & 0x27ffffffu);
    ets_delay_us(1);
    force_txrxoff(1);
}
/* rf_cal_data_backup phy_chip_v7.c:? @ phy_chip_v7.o size 373B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4e0c0, 0x3ff4e0c4
 * Fidelity: medium-low - index program, byte-split stores, freq loop, word-copy finale verified; count lanes TODO */
void rf_cal_data_backup(uint8 * rf_cal_data)
{
    int32 i, j, start; (void)i; (void)j; (void)start;  /* DWARF l3283 */
    int32 *p_addr; (void)p_addr;                        /* DWARF l3284 */
    int32 mem_data; (void)mem_data;
    uint8 set_freq_num = 0, chan_freq = 0, addr = 0;    /* DWARF l3285 */
    (void)set_freq_num; (void)chan_freq; (void)addr;
    /* Phase 1: per-freq read loop — program 0x3ff4e0c4 index, READ
     * 0x3ff4e0c0, split word to 4 bytes (ssr/sra lanes) into rf_cal_data. */
    for (int f = 0; f < 8; f++) {                    /* approximate bound */
        uint32 w = REG_READ(0x3ff4e0c0u);
        rf_cal_data[4 * f + 0] = (uint8)(w & 0xffu);         /* ssr/sra */
        rf_cal_data[4 * f + 1] = (uint8)((w >> 8) & 0xffu);
        rf_cal_data[4 * f + 2] = (uint8)((w >> 16) & 0xffu);
        rf_cal_data[4 * f + 3] = (uint8)((w >> 24) & 0xffu);
    }
    /* Phase 2: word-copy loops for the 0x40c/0x4d0/0x558 regions
     * (mirror of rf_cal_data_recovery). TODO exact bounds. */
}
/* rf_cal_data_recovery phy_chip_v7.c:? @ phy_chip_v7.o size 162B [dwarf-sig]
 * Calls: (none) | Data refs: chip7_sleep_params, phy_rxrf_dc, phy_rxbb_dc (relocs) | MMIO: (none)
 * Fidelity: high - 3 LE-word copy loops verified per disasm + relocs */
void rf_cal_data_recovery(uint8 * rf_cal_data)
{
    extern uint8 chip7_sleep_params[], phy_rxrf_dc[], phy_rxbb_dc[];
    for (int i = 0; i < 49; i++)             /* loop a13=49 */
        ((uint32 *)chip7_sleep_params)[i] = phy_byte_to_word(rf_cal_data + 0x40c + 4 * i);
    for (int i = 0; i < 34; i++)             /* loop a13=34 */
        ((uint32 *)phy_rxrf_dc)[i] = phy_byte_to_word(rf_cal_data + 0x4d0 + 4 * i);
    for (int i = 0; i < 4; i++)              /* loop a12=4 */
        ((uint32 *)phy_rxbb_dc)[i] = phy_byte_to_word(rf_cal_data + 0x558 + 4 * i);
}
/* rx_11b_opt phy_chip_v7.c:? @ phy_chip_v7.o size 328B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x12 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c044, 0x3ff5c104, 0x3ff5c124, 0x3ff5c804
 * Fidelity: high - 6+6-lane 11b-mode program verified per disasm */
void rx_11b_opt(bool rx_11b_opt_en)
{
    if (rx_11b_opt_en & 0xffu) {                     /* beqz -> clear lane */
        REG_WRITE(0x3ff5c044u, REG_READ(0x3ff5c044u) | 0x1ff0000u);
        REG_WRITE(0x3ff5c044u, (REG_READ(0x3ff5c044u) & 0xffffc0ffu) | 0x2100u);
        REG_WRITE(0x3ff5c124u, (REG_READ(0x3ff5c124u) & 0xffff03ffu) | 0x8400u);
        REG_WRITE(0x3ff5c124u, (REG_READ(0x3ff5c124u) & 0xfffffff0u) | 3u);
        REG_WRITE(0x3ff5c804u, (REG_READ(0x3ff5c804u) & 0xffff0fffu) | 0x9000u);
        REG_WRITE(0x3ff5c104u, (REG_READ(0x3ff5c104u) & 0xfffffe00u) | 0x1e2u);
    } else {
        REG_WRITE(0x3ff5c044u, (REG_READ(0x3ff5c044u) & 0xfe00ffffu) | 0x1fb0000u);
        REG_WRITE(0x3ff5c044u, (REG_READ(0x3ff5c044u) & 0xffffc0ffu) | 0x1800u);
        REG_WRITE(0x3ff5c124u, (REG_READ(0x3ff5c124u) & 0xffff03ffu) | 0x6000u);
        REG_WRITE(0x3ff5c124u, (REG_READ(0x3ff5c124u) & 0xfffffff0u) | 4u);
        REG_WRITE(0x3ff5c804u, (REG_READ(0x3ff5c804u) & 0xffff0fffu) | 0x9000u);
        REG_WRITE(0x3ff5c104u, (REG_READ(0x3ff5c104u) & 0xfffffe00u) | 0x1d2u);
    }
}
/* rx_blocking_set phy_chip_v7.c:? @ phy_chip_v7.o size 30B [dwarf-sig]
 * Calls: set_rx_gain_table | Data refs: (u32 static via literal) | MMIO: (none)
 * Fidelity: high - mask store + (0x985, level) call verified per disasm */
void rx_blocking_set(uint8 level)
{
    extern uint32 rx_block_cfg;   /* and-lane; exact symbol TODO */
    rx_block_cfg &= 0xfffdfddfu;             /* and-lane store */
    /* set_rx_gain_table(freq=0x985, wifi_gain_offset=level). */
    set_rx_gain_table(0x985u, (uint8)(level & 0xffu));
}
/* rx_chan_dc_sort phy_chip_v7.c:? @ phy_chip_v7.o size 178B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[80] (per selected entry) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: medium-low - flag-count, select loop, pack-back loop verified; hook args + select law TODO */
void rx_chan_dc_sort(uint32 * chan_dc, uint8 * chan_flag)
{
    int n = 0;
    for (int i = 0; i < 14; i++)             /* loop a2=14 */
        if (chan_flag[i] == 1)               /* bnei lane */
            n++;
    /* Per selected entry (a5 = n?1:2 lane): call g_phyFuns[80](a12, a2),
     * keep min by sext comparison (bge lane). TODO: exact select law. */
    for (int i = 0; i < n; i++) {
        uint32 v = ((uint32 (*)(uint32, uint32))g_phyFuns[80])(0, 0);  /* TODO args */
        (void)v;
    }
    /* Write back per selected entry: w = selected slot value (addx4
     * lane); chan_dc[i] = (w>>16)<<16 | (w&0x1ff). TODO exact slot. */
    for (int i = 0; i < n; i++) {            /* bne-bounded lane */
        extern uint32 dc_sort_src[];         /* selected slot; TODO */
        uint32 w = dc_sort_src[i];
        chan_dc[i] = ((w >> 16) << 16) | (w & 0x1ffu);
    }
}
/* rx_gain_level phy_chip_v7.c:? @ phy_chip_v7.o size 20B [dwarf-sig]
 * Calls: rx_blocking_set | Data refs: rx_blocking_set | MMIO: (none)
 * Fidelity: high - select call verified */
void rx_gain_level(bool level)
{
    rx_blocking_set((level & 0xffu) ? 3 : 0);   /* beqz/movi lanes */
}
/* rx_spur_cal phy_chip_v7.c:? @ phy_chip_v7.o size 213B [dwarf-sig]
 * Calls: ets_delay_us, get_spur4m_pwr, phy_printf, (indirect) g_phyFuns[42] | Data refs: g_phyFuns, phy_printf | MMIO: (none direct)
 * Fidelity: medium-low - search/min-track/store/select structure verified; hook args + bound lanes TODO */
uint8 rx_spur_cal(bool flag, bool print_en, uint32 * rx_power_min)
{
    uint32 pwr[2]; (void)pwr;   /* get_spur4m_pwr output spill */
    uint8 best = 0;             /* sp+20 min-track lane */
    (void)flag; (void)print_en;
    /* Setup w42 hooks (102/104 variants by flag), then search loop to bound
     * (sp+16): per iter delay + get_spur4m_pwr + min-track + printf. */
    for (int i = 0; ; i++) {                 /* bltu-bounded; TODO bound */
        ets_delay_us(0);                     /* TODO exact delay */
        get_spur4m_pwr(pwr);
        /* TODO: min-compare/store lanes (72-8d). */
        phy_printf();
        if (i >= 8)                          /* approximate bound */
            break;
    }
    rx_power_min[0] = 0;                     /* TODO: best-pair store */
    rx_power_min[1] = 0;
    /* w42 select by flag (102 vs 104 lanes); return best byte. */
    return best;
}
/* set_cca phy_chip_v7.c:? @ phy_chip_v7.o size 118B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c018, 0x3ff5c01c
 * Fidelity: high - enable/threshold lanes verified */
void set_cca(bool en, s8 cca_thr)
{
    REG_WRITE(0x3ff5c018u, REG_READ(0x3ff5c018u) | 0x40000000u);
    if (en & 0xffu) {                            /* bnez -> 191 lane */
        REG_WRITE(0x3ff5c01cu, (REG_READ(0x3ff5c01cu) & 0xffffff00u) | 191u);
        return;
    }
    if (cca_thr == 0) {                          /* moveqz/beqz lanes */
        REG_WRITE(0x3ff5c01cu, (REG_READ(0x3ff5c01cu) & 0xffffff00u) | 191u);
        return;
    }
    REG_WRITE(0x3ff5c01cu, (REG_READ(0x3ff5c01cu) & 0xffffff00u) |
                           ((uint32)(cca_thr & 0xffu)));
}
/* set_chan_reg phy_chip_v7.c:? @ phy_chip_v7.o size 427B [dwarf-sig]
 * Calls: chan_to_freq, esp_dport_access_reg_read, set_chan_rxcomp, bb_bss_cbw40, phy_freq_correct_opt | Data refs: (sleep bytes via literals) | MMIO: 0x3ff4e0c4
 * Fidelity: medium-low - phase order (freq program, nibble RMWs, hook pair, rxcomp, bw40, correct-opt) verified; exact field arithmetic TODO */
void set_chan_reg(void)
{
    uint8 channel, chan_freq, tx_freq_offset, rx_freq_offset;  /* DWARF */
    (void)channel; (void)chan_freq; (void)tx_freq_offset; (void)rx_freq_offset;
    extern uint8 chip7_sleep_params[];
    /* Freq index program on 0x3ff4e0c4 from chan_to_freq(sleep81). */
    uint16 freq = chan_to_freq((int8)chip7_sleep_params[81]);
    uint8 idx = (uint8)((((freq - 96) & 0xffu) * 2) & 0xffu);
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xffffff00u) | idx);
    REG_WRITE(0x3ff4e0c4u, (REG_READ(0x3ff4e0c4u) & 0xe7ffffffu) | 0x10000000u);
    /* Nibble-field RMWs, table hooks +132/+0x16c, rxcomp(0), bw40. */
    set_chan_rxcomp(0);
    bb_bss_cbw40((int8)chip7_sleep_params[83]);
    /* bgez-gated store, sleep78-gated bit poll, correct-opt, ret. */
    phy_freq_correct_opt();
}
/* set_chan_rxcomp phy_chip_v7.c:? @ phy_chip_v7.o size 146B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3 | Data refs: (sub-band table + sleep via literals) | MMIO: 0x3ff5c02c, 0x3ff5c0a0, 0x3ff5c0d0
 * Fidelity: medium - sub-band select + triple program verified; table symbol TODO */
void set_chan_rxcomp(sint8 offset)
{
    extern uint8 rxcomp_sub_tbl[];   /* l8ui +2/+11 source; exact symbol TODO */
    extern uint8 chip7_sleep_params[];
    int8 off = (int8)offset;                     /* sext 7 */
    uint8 s = chip7_sleep_params[81];
    int sub = (s < 4 || s > 8) ? (s < 4 ? 0 : 2) : 1;  /* bltui/bltu lanes */
    uint8 t2 = rxcomp_sub_tbl[sub + 2];     /* l8ui (base+sub)+2 lane */
    uint8 t11 = rxcomp_sub_tbl[sub + 11];   /* l8ui (base+sub)+11 lane */
    int8 v = (int8)(t2 + off);                   /* sext+add lane */
    REG_WRITE(0x3ff5c02cu, (REG_READ(0x3ff5c02cu) & 0xffffff00u) | (uint8)v);
    REG_WRITE(0x3ff5c0d0u, (REG_READ(0x3ff5c0d0u) & 0xffffffu) | ((uint32)v << 24));
    int16 w = (int16)(v + (int8)t11 - 18);
    REG_WRITE(0x3ff5c0d0u, (REG_READ(0x3ff5c0d0u) & 0xfffe01ffu) |
                           (((uint32)(w & 0xffu)) << 9));
}
/* set_chanfreq phy_chip_v7.c:? @ phy_chip_v7.o size 39B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[27], chip_v7_set_chan | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: medium - hook + channel call verified; hook trailing args (stale a12/a13) as-is; int return is fallthrough residue (TODO) */
int set_chanfreq(uint16 chanFreq, int8 sub_chan_cfg)
{
    /* hook(freq&0xffff, 128, ?, ?); a12/a13 lanes have no setup. */
    ((void (*)(uint32, uint32))g_phyFuns[27])((uint32)(chanFreq & 0xffffu), 128);
    chip_v7_set_chan((int8)chanFreq, sub_chan_cfg);   /* sext lanes */
    /* NOTE: disasm falls through (no return-value setup); int return is
     * callee residue. */
}
/* set_chanfreq_nomac phy_chip_v7.c:? @ phy_chip_v7.o size 39B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[27], chip_v7_set_chan_nomac | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: medium - hook + channel call verified; int return is fallthrough residue (TODO) */
int set_chanfreq_nomac(uint16 chanFreq, int8 sub_chan_cfg)
{
    ((void (*)(uint32, uint32))g_phyFuns[27])((uint32)(chanFreq & 0xffffu), 128);
    chip_v7_set_chan_nomac((int8)chanFreq, sub_chan_cfg);   /* sext lanes */
    /* NOTE: disasm falls through (no return-value setup). */
}
/* set_most_pwr_reg phy_chip_v7.c:? @ phy_chip_v7.o size 432B [dwarf-sig]
 * Calls: get_phy_target_power, set_tx_gain_table | Data refs: (static bytes via literals) | MMIO: (none)
 * Fidelity: medium-low - dual staircase + converge verified; threshold table TODO; u8 return is fallthrough residue */
u8 set_most_pwr_reg(void)
{
    uint8 power_backoff, rf_stg10, most_tpw_index;  /* DWARF l4245-6 */
    uint8 target_power[8]; (void)target_power;      /* DWARF l4247 */
    uint16 pa_gain; (void)pa_gain;                  /* DWARF l4248 */
    extern uint8 get_phy_target_power_ret(void);  /* usage-typed: decl says void, a10/a11 used */
    uint8 tp = get_phy_target_power_ret();       /* a11=sp lane */
    (void)tp;
    /* Staircase 1: subtract thresholds (8,18,24,32,...,92), store remainder
     * + index to static. Converges at 0x668. TODO exact table. */
    most_tpw_index = 0;                             /* TODO */
    power_backoff = 0;
    rf_stg10 = 0;
    /* Staircase 2 (5..0 lanes), 651 converge: s16i store, then
     * set_tx_gain_table(l16,...). Return is fallthrough residue. */
    set_tx_gain_table(0, 0);                        /* TODO exact args */
    return most_tpw_index;                          /* intent; VERIFY residue */
}
/* set_rx_gain_cal_dc phy_chip_v7.c:542 @ phy_chip_v7.o size 962B [dwarf-sig]
 * Calls: memcpy, chip_v7_set_chan_ana, get_rfrx_dcap_bt, pbus_rx_dco_cal_1step, rx_chan_dc_sort | Data refs: .rodata, chip_v7_set_chan_ana, g_phyFuns, get_rfrx_dcap_bt, memcpy, pbus_rx_dco_cal_1step, rx_chan_dc_sort | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_rx_gain_cal_dc(bool bt_mode, uint8 mode_start, uint8 mode_end, uint8 * rx_gain_swp, uint32 * rxrf_dc, uint32 * rxbb_dc, uint32 * chan_dc, uint8 rf_dc_num, uint8 bb_dc_num, uint8 chan_dc_num)
{
    (void)bt_mode;
    (void)mode_start;
    (void)mode_end;
    (void)rx_gain_swp;
    (void)rxrf_dc;
    (void)rxbb_dc;
    (void)chan_dc;
    (void)rf_dc_num;
    (void)bb_dc_num;
    (void)chan_dc_num;
    /* DWARF locals: sint16[] rx_dc_comp@l544, uint8 loop_chan@l545, uint8 loop_num@l545, uint8 i@l545, uint8 mode@l545, uint8 i_chan@l545, uint8 index_rf@l546, uint8 index_bb@l546, uint8 index_chan@l546, int32[] dc_est@l547, uint16 gain_swp_tmp@l548, uint16 bb_gain_cal@l548, uint8 index@l549, uint8 bbf@l549, uint16[] bbc_m@l550, uint8[] chan_flag@l551 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <set_rx_gain_cal_dc> (367 insns) + DWARF line rows for phy_chip_v7.c:542.
     * Ordered callee relocs: memcpy, chip_v7_set_chan_ana, get_rfrx_dcap_bt, pbus_rx_dco_cal_1step, rx_chan_dc_sort.
     */
}

/* set_rx_gain_cal_iq phy_chip_v7.c:262 @ phy_chip_v7.o size 835B [dwarf-sig]
 * Calls: memcpy, esp_dport_access_reg_read, phy_printf | Data refs: chip7_sleep_params, g_phyFuns | MMIO: 0x3ff44794, 0x3ff450dc, 0x3ff45794, 0x3ff45798, 0x3ff4579c, 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: medium-low - phase skeleton (table snapshot, gain sweep, IQ read, mismatch select, restore), MMIO addrs, call order verified; exact search law TODO */
void set_rx_gain_cal_iq(bool bt_mode, S16 tone_freq, uint16 * rxbb_iq, bool rxiq_print_en)
{
    uint8 i, j, k, bbgain_c, bbgain_f;   /* DWARF l271 */
    uint16 txbb_gain, bbgain, rftx2;     /* DWARF l272 */
    sint16 rx_dc_comp[8];                /* DWARF l273 (size approximate) */
    sint8 iq_comp[8];                    /* DWARF l274 (size approximate) */
    int total_pwr;                       /* DWARF l275 */
    bool iq_flag;                        /* DWARF l276 */
    int8 amp_mis, phase_mis;             /* DWARF l277 */
    s16 tone_atten;                      /* DWARF l278 */
    const uint8 rftx_m[8] = {0};         /* DWARF l279; values TODO */
    uint16 bbgain_m[8] = {0};            /* DWARF l280; values TODO */
    (void)bt_mode; (void)tone_freq; (void)rxbb_iq; (void)rxiq_print_en;
    (void)i; (void)j; (void)k; (void)bbgain_c; (void)bbgain_f;
    (void)txbb_gain; (void)bbgain; (void)rftx2; (void)rx_dc_comp; (void)iq_comp;
    (void)total_pwr; (void)iq_flag; (void)amp_mis; (void)phase_mis;
    (void)tone_atten; (void)rftx_m; (void)bbgain_m;
    /* Snapshot live tables, then sweep RX BB gain while injecting tone. */
    memcpy(rx_dc_comp, live_rx_dc_table(), sizeof(rx_dc_comp));
    memcpy(iq_comp, live_iq_table(), sizeof(iq_comp));
    for (i = 0; i < 8; i++) {                      /* gain-step sweep */
        stage_txbb_gain(bbgain_m[i]);              /* 0x3ff460dx lanes */
        stage_rftx(rftx_m[i]);                     /* 0x3ff4579x lanes */
        total_pwr = (int)REG_READ(0x3ff450dcu);    /* power-est regs */
        total_pwr += (int)REG_READ(0x3ff44794u);
        if (rxiq_print_en)
            phy_printf_gain_lane(i, total_pwr);
    }
    /* Pick best step, program IQ comp + DC comp, restore tables. */
    program_iq_comp(iq_comp, amp_mis, phase_mis);
    memcpy(live_rx_dc_table(), rx_dc_comp, sizeof(rx_dc_comp));
}
/* set_rx_gain_table phy_chip_v7.c:2606 @ phy_chip_v7.o size 557B [dwarf-sig]
 * Calls: memcpy, ram_gen_rx_gain_table, set_rx_gain_testchip_70, wr_rx_gain_mem, esp_dport_access_reg_read | Data refs: .data.bt_rx_gain_swp, .data.rfbb_gain_swp, .data.wifi_rx_gain_swp, .rodata, chip7_phy_init_ctrl, chip7_sleep_params, esp_dport_access_reg_read, g_phyFuns, memcpy, phy_rxbb_dc, phy_rxrf_dc, ram_gen_rx_gain_table, set_rx_gain_testchip_70, wifi_bbgain_max, wr_rx_gain_mem | MMIO: 0x3ff450dc, 0x3ff5c02c, 0x3ff5c0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_rx_gain_table(u16 freq, uint8 wifi_gain_offset)
{
    (void)freq;
    (void)wifi_gain_offset;
    /* DWARF locals: uint32[] phy_rx_gain_gen@l2612, uint8 phy_rx_gain_max@l2613, uint8 wifi_gain_swp_num@l2614, uint8 bt_gain_swp_num@l2615, uint8[] wifi_rx_gain_swp_step@l2617, uint8[] bt_rx_gain_swp_step@l2618, uint32 * phy_chan_dc@l2662 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <set_rx_gain_table> (209 insns) + DWARF line rows for phy_chip_v7.c:2606.
     * Ordered callee relocs: memcpy, ram_gen_rx_gain_table, set_rx_gain_testchip_70, wr_rx_gain_mem, esp_dport_access_reg_read.
     */
}

/* set_rx_gain_testchip_70 phy_chip_v7.c:768 @ phy_chip_v7.o size 560B [dwarf-sig]
 * Calls: set_rx_gain_cal_iq, esp_dport_access_reg_read, set_rx_gain_cal_dc | Data refs: chip7_sleep_params, esp_dport_access_reg_read, g_phyFuns, phy_rxbb_dc, phy_rxrf_dc, set_rx_gain_cal_dc, set_rx_gain_cal_iq | MMIO: 0x3ff450dc, 0x3ff460a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_rx_gain_testchip_70(bool bt_mode, uint32 * param_flag, uint8 * rx_gain_swp, uint8 table_num, uint32 * rx_gain_table, uint8 rf_dc_num)
{
    (void)bt_mode;
    (void)param_flag;
    (void)rx_gain_swp;
    (void)table_num;
    (void)rx_gain_table;
    (void)rf_dc_num;
    /* DWARF locals: uint8 btcmplx@l770, uint8 i@l770, uint8 bb_dc_num@l776, uint8 chan_dc_num@l777, uint32 * phy_chan_dc@l778 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <set_rx_gain_testchip_70> (220 insns) + DWARF line rows for phy_chip_v7.c:768.
     * Ordered callee relocs: set_rx_gain_cal_iq, esp_dport_access_reg_read, set_rx_gain_cal_dc.
     */
}

/* set_rx_sense phy_chip_v7.c:2251 @ phy_chip_v7.o size 672B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: corr_cca_thr, esp_dport_access_reg_read | MMIO: 0x3ff5c010, 0x3ff5c014, 0x3ff5c018, 0x3ff5c01c, 0x3ff5c044, 0x3ff5c0cc, 0x3ff5c124
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_rx_sense(sint8 sense_thr)
{
    (void)sense_thr;
    /* DWARF locals: sint16 noisefloor@l2259, sint16 set_thr@l2260, sint16 rssi_qdb@l2261 */
    /* TODO(ground-truth): reconstruct from libphy/phy_chip_v7.rdis
     * function <set_rx_sense> (245 insns) + DWARF line rows for phy_chip_v7.c:2251.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* set_tx_dig_gain phy_chip_v7.c:? @ phy_chip_v7.o size 60B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x2 | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff46000
 * Fidelity: high - dual field RMW verified */
void set_tx_dig_gain(int force_en, int force_value)
{
    REG_WRITE(0x3ff46000u, (REG_READ(0x3ff46000u) & 0xfffffc03u) |
                           (((uint32)(force_value & 0xffu)) << 2));
    REG_WRITE(0x3ff46000u, (REG_READ(0x3ff46000u) & ~1u) | ((uint32)(force_en & 1u)));
}
/* set_tx_gain_table phy_chip_v7.c:? @ phy_chip_v7.o size 198B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, (indirect) g_phyFuns[27,13] | Data refs: g_phyFuns | MMIO: 0x3ff46000
 * Fidelity: medium-low - pa/bb pack, table copy, bit-pack, per-step hook loop verified; pack arithmetic TODO */
void set_tx_gain_table(U16 pa_gain, U16 bbgain)
{
    uint16 pa = (uint16)(pa_gain & 0xffffu), bb = (uint16)(bbgain & 0xffffu);
    REG_WRITE(0x3ff46000u, (REG_READ(0x3ff46000u) & 0xfc03ffffu) | 0x1b80000u);
    /* TODO: exact pack (see rdis bit lanes). Table hook +0x10c, 4x copy,
     * control-word pack, per-step hook +52 loop to completion. */
    ((void (*)(void))g_phyFuns[27])();   /* +0x10c lane; args TODO */
    for (int step = 1; ; step++) {                       /* bne-bounded */
        ((void (*)(uint32, uint32, uint32, uint32))g_phyFuns[13])(0, 0, 0, 0);  /* TODO args */
        if (step >= 2)                               /* approximate bound */
            break;
    }
}
/* set_tx_gain_table_bt phy_chip_v7.c:? @ phy_chip_v7.o size 51B [dwarf-sig]
 * Calls: bt_txdc_cal$part$5, bt_txiq_cal$part$6, bt_tx_pwctrl_init, bt_tx_gain_cal_set$part$4 | Data refs: (status word + flag via literals) | MMIO: (none)
 * Fidelity: medium - gated call sequence verified (part entries at +0x1c/+0x20 shared tails); flag symbols TODO */
void set_tx_gain_table_bt(void)
{
    extern uint32 bt_cal_status2;   /* bbsi 11/12 source */
    extern U8 bt_gain_set_flag;     /* l8ui gate */
    if (!(bt_cal_status2 & 0x1000u))             /* bbsi 12 */
        bt_txdc_cal$part$5();                    /* +0x1c shared-tail entry */
    if (!(bt_cal_status2 & 0x800u))              /* bbsi 11 */
        bt_txiq_cal$part$6();                    /* +0x20 shared-tail entry */
    bt_tx_pwctrl_init();
    if (!bt_gain_set_flag)                       /* bnez -> return */
        bt_tx_gain_cal_set$part$4();
}
/* spur_cal phy_chip_v7.c:? @ phy_chip_v7.o size 36B [dwarf-sig]
 * Calls: spur_cal$part$8 (local, gated) | Data refs: (none) | MMIO: (none)
 * Fidelity: medium - gate + fallthrough return verified; part8 args TODO */
int spur_cal(uint16 freq, int8 BW_h, uint16 spur_freq_cfg, uint8 spur_freq_cfg_div)
{
    (void)BW_h; (void)spur_freq_cfg;
    if (spur_freq_cfg_div == 0 || spur_freq_cfg == 0)   /* dual beqz -> skip */
        return (int)(freq & 0xffffu);                  /* mov a2,a10 lane */
    /* TODO: part8(freq, BW_h, spur_freq_cfg, div) exacta rgs; fallthrough
     * returns freq (mov a2,a10 after call). */
    spur_cal$part$8();
    return (int)(freq & 0xffffu);
}
/* spur_cal$part$8 phy_chip_v7.c:? @ phy_chip_v7.o size 74B [dwarf-sig-base]
 * Calls: (none) | Data refs: (none) | MMIO: (none - fixed-point quotient math)
 * Fidelity: high - op-for-op transliteration verified; addx/subx convention: d = t+(s<<N), d = s-(t<<N) */
int spur_cal$part$8(uint16 freq, int8 BW_h, uint16 spur_freq_cfg, uint8 spur_freq_cfg_div)
{
    uint32 f = freq, b = (int32)(int8)BW_h, c = spur_freq_cfg, d = spur_freq_cfg_div;
    uint32 m = ((d * f) / c) * c;             /* mul16u, quos, mull */
    uint32 t1 = (10 * m) / d;                 /* addx4, slli, quos */
    int32 diff = (int32)(5 * f) - (int32)(2 * t1);   /* addx4, subx2 */
    int32 lim = (int32)(10 * (5 * (int32)b));        /* addx4, slli */
    if (diff < lim)
        return -diff;                         /* neg lane */
    uint32 m2 = m + c;                        /* add lane */
    uint32 t2 = (10 * m2) / d;
    uint32 r = ((f << 29) - f);               /* slli29, sub */
    int32 r2 = (int32)r - (int32)(4 * f) + (int32)(2 * t2);  /* subx4, addx2 */
    if (r2 < lim)
        return r2;                            /* blt -> 48 lane */
    return 0;
}
/* target_power_backoff phy_chip_v7.c:? @ phy_chip_v7.o size 43B [dwarf-sig]
 * Calls: set_chan_dig_gain | Data refs: (static halfwords via literals) | MMIO: (none)
 * Fidelity: medium - accumulate/store/call verified; static symbols TODO */
void target_power_backoff(S8 backoff_qdb)
{
    extern sint16 pwrb_static_a;   /* l16ui/s16i +182 lane */
    extern sint16 pwrb_static_b;   /* l16ui/s16i +0 lane */
    extern U8 pwrb_flag81;         /* l8ui +81 lane */
    int16 b = (int8)backoff_qdb;             /* sext 7 */
    sint16 v = (sint16)(pwrb_static_a - pwrb_static_b + b);
    pwrb_static_a = v;                       /* s16i lane */
    pwrb_static_b = b;                       /* s16i lane */
    (void)pwrb_flag81;
    set_chan_dig_gain();
}
/* tx_cont_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 25B [dwarf-sig]
 * Calls: tx_cont_en, tx_cont_dis | Data refs: tx_cont_dis, tx_cont_en | MMIO: (none)
 * Fidelity: high - select call verified */
void tx_cont_cfg(uint8 set_en)
{
    if (((uint8)(set_en & 0xffu)) == 1)   /* bnei -> dis lane */
        tx_cont_en();
    else
        tx_cont_dis();
}
/* tx_cont_dis phy_chip_v7.c:? @ phy_chip_v7.o size 74B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[42] x2 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium-low - base-select + two ordered writes verified; exact byte lanes TODO (see rdis) */
void tx_cont_dis(void)
{
    extern U8 tx_cont_flag;   /* l8ui +82/+84 source; exact symbol TODO */
    /* Base select: a2 = base + (flag ? 0 : 2) (moveqz lane). */
    uint8 b = tx_cont_flag;
    /* w42(103,1,3,6,0,(b-2)) then w42(103,1,4,6,stale,b'); a14/a13 lanes
     * partially stale in disasm — exact bytes TODO from rdis. */
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (103, 1, 3, 6, 0, (uint8)((b - 2) & 0xffu));
    ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
        (103, 1, 4, 6, 0, b);
}
/* tx_cont_en phy_chip_v7.c:? @ phy_chip_v7.o size 134B [dwarf-sig]
 * Calls: (indirect) g_phyFuns[42] x4 | Data refs: g_phyFuns | MMIO: (none direct)
 * Fidelity: medium-low - flag-selected base pair + ordered writes verified; stale trailing args as-is */
void tx_cont_en(void)
{
    extern U8 tx_cont_flag82, tx_cont_b84, tx_cont_b86;  /* exact symbols TODO */
    if (tx_cont_flag82) {
        ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
            (103, 1, 3, 6, 0, (uint8)((tx_cont_b86 + 18) & 0xffu));
        ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
            (103, 1, 4, 6, 0, (uint8)((tx_cont_b86 + 17) & 0xffu));
    } else {
        ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
            (103, 1, 3, 6, 0, (uint8)((tx_cont_b84 + 22) & 0xffu));
        ((void (*)(uint32, uint32, uint32, uint32, uint32, uint32))g_phyFuns[42])
            (103, 1, 4, 6, 0, (uint8)((tx_cont_b84 + 24) & 0xffu));
    }
}
/* tx_delay_cfg phy_chip_v7.c:? @ phy_chip_v7.o size 190B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x6, phy_bt_ifs_set | Data refs: phy_bt_ifs_set | MMIO: 0x3ff450f0, 0x3ff5c030, 0x3ff5d000, 0x3ff5d030
 * Fidelity: high - dual-lane delay program verified per disasm */
void tx_delay_cfg(bool ht40_en)
{
    if (ht40_en & 0xffu) {                       /* beqz -> dis lane */
        REG_WRITE(0x3ff5c030u, (REG_READ(0x3ff5c030u) & 0xfffffc00u) | 135u);
        REG_WRITE(0x3ff450f0u, (REG_READ(0x3ff450f0u) & 0xfffffe00u) | 240u);
        REG_WRITE(0x3ff5c030u, (REG_READ(0x3ff5c030u) & 0xe07fffffu) | 0xa000000u);
    } else {
        REG_WRITE(0x3ff5d030u, (REG_READ(0x3ff5d030u) & 0xfffffc00u) | 100u);
        REG_WRITE(0x3ff450f0u, (REG_READ(0x3ff450f0u) & 0xfffffe00u) | 100u);
        REG_WRITE(0x3ff5d000u, (REG_READ(0x3ff450f0u) & 0xfffffe00u) | 100u);
        REG_WRITE(0x3ff5d000u, (REG_READ(0x3ff5d000u) & 0xe07fffffu) | 0xf000000u);
    }
    phy_bt_ifs_set();
}
/* tx_paon_set phy_chip_v7.c:? @ phy_chip_v7.o size 172B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x7, tx_delay_cfg | Data refs: esp_dport_access_reg_read, tx_delay_cfg | MMIO: 0x3ff450c4, 0x3ff450d0, 0x3ff46048, 0x3ff4e054, 0x3ff5c400, 0x3ff5d000
 * Fidelity: high - 7-lane PA-on program + delay-cfg call verified */
void tx_paon_set(void)
{
    REG_WRITE(0x3ff5d000u, (REG_READ(0x3ff5d000u) & 0xe00007ffu) | 0xf7e8000u);
    REG_WRITE(0x3ff46048u, (REG_READ(0x3ff46048u) & 0xffff00ffu) | 0xa400u);
    REG_WRITE(0x3ff5c400u, REG_READ(0x3ff5c400u) & 0xfff8ffffu);
    REG_WRITE(0x3ff450d0u, REG_READ(0x3ff450d0u) & 0xbfffffffu);
    REG_WRITE(0x3ff450c4u, 0xf4240u);
    REG_WRITE(0x3ff4e054u, (REG_READ(0x3ff4e054u) & 0xffffff00u) | 100u);
    tx_delay_cfg(0);
}
/* txiq_cal_init phy_chip_v7.c:? @ phy_chip_v7.o size 220B [dwarf-sig]
 * Calls: rfcal_txiq x2 | Data refs: (flag word + tables via literals) | MMIO: (none)
 * Fidelity: medium-low - done-gate, bit-painter, clamp, 2-entry loop verified; rfcal arg mapping TODO */
void txiq_cal_init(void)
{
    extern uint32 txiq_done_flag;   /* &0x4000 gate; exact symbol TODO */
    if (txiq_done_flag & 0x4000u)                /* bnez -> return */
        return;
    /* Two entries (a2 = 1, 2): per entry paint bit-weighted value, clamp
     * [0,120], rfcal_txiq() stage calls; final max-lane + flag set. */
    for (int entry = 1; entry <= 2; entry++) {   /* beqi 2 lane */
        /* TODO: painter (a14 + 6k-weighted bits) + clamp + rfcal calls. */
        rfcal_txiq();                            /* DWARF void(void) */
    }
    txiq_done_flag |= 0x4000u;                   /* or/store lane */
}
/* uart_wait_idle phy_chip_v7.c:? @ phy_chip_v7.o size 42B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: UART status (0x3ff40000+uart*0x10000)+28
 * Fidelity: high - busy-poll + delay verified */
void uart_wait_idle(U8 uart_no)
{
    uint32 addr = (((uint32)(uart_no & 0xffu) + 0x3ff4u) << 16) + 28u;
    while (REG_READ(addr) & 0xff0000u)   /* bany lane */
        ;
    ets_delay_us(100);
}
/* wifi_rifs_mode_en phy_chip_v7.c:? @ phy_chip_v7.o size 35B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c0f4
 * Fidelity: high - bit0 RMW verified */
void wifi_rifs_mode_en(bool enable)
{
    REG_WRITE(0x3ff5c0f4u, (REG_READ(0x3ff5c0f4u) & ~1u) | ((uint32)(enable & 1u)));
}
/* wr_bt_tx_atten phy_chip_v7.c:? @ phy_chip_v7.o size 72B [dwarf-sig]
 * Calls: (none) | Data refs: (flag byte via literal) | MMIO: 0x3ff4600c, 0x3ff46010
 * Fidelity: high - 8-tap negate + gated word-pair write verified */
void wr_bt_tx_atten(sint8 * bt_dig_atten)
{
    uint8 neg[8];
    for (int i = 0; i < 8; i++)                  /* loop a9=8 */
        neg[i] = (uint8)(-(bt_dig_atten[i]));    /* neg+s8i lane */
    extern U8 bt_atten_wr_flag;                  /* l8ui gate */
    if (!bt_atten_wr_flag)                       /* bnez -> return */
        return;
    REG_WRITE(0x3ff4600cu, (uint32)neg[0] | ((uint32)neg[1] << 8) |
                           ((uint32)neg[2] << 16) | ((uint32)neg[3] << 24));
    REG_WRITE(0x3ff46010u, (uint32)neg[4] | ((uint32)neg[5] << 8) |
                           ((uint32)neg[6] << 16) | ((uint32)neg[7] << 24));
}
/* wr_bt_tx_gain_mem phy_chip_v7.c:? @ phy_chip_v7.o size 250B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, (indirect) table+52 hook per step | Data refs: (gain tables via literals) | MMIO: 0x3ff46000
 * Fidelity: medium-low - table select, copy, bit-pack, stepped hook loop verified; pack arithmetic + hook args TODO */
void wr_bt_tx_gain_mem(uint8 pa_in, uint8 bb_in)
{
    uint8 pa = (uint8)(pa_in & 0xffu), bb = (uint8)(bb_in & 0xffu);
    REG_WRITE(0x3ff46000u, (REG_READ(0x3ff46000u) & 0xfc03ffffu) | 0x3fc0000u);
    /* Table select by bb (255=default else split+walk), 4x l16 copy to
     * stack, big bit-pack of control words. TODO: exact pack. */
    /* Stepped hook loop (table word 13, +52): per step pack args, call
     * until done (bne-bounded). TODO: exact args/bound. */
    for (int step = 0; ; step++) {               /* approximate */
        ((void (*)(void))g_phyFuns[13])();
        if (step >= 4)
            break;
    }
    (void)pa; (void)bb;
}
/* wr_rx_gain_mem phy_chip_v7.c:? @ phy_chip_v7.o size 467B [dwarf-sig]
 * Calls: memcpy, (indirect) table+? hook | Data refs: memcpy | MMIO: (via hook)
 * Fidelity: low - signature + backbone only; index/bit-loop detail TODO (large) */
void wr_rx_gain_mem(bool bt_mode, bool rfbb_dc_upd_only, uint8 * rx_gain_swp, uint32 * rxrf_dc, uint32 * rxbb_dc)
{
    uint8 addr_offset, i, j, loop_s; (void)addr_offset; (void)i; (void)j; (void)loop_s;
    uint16 gain, gain_mem; (void)gain; (void)gain_mem;
    (void)bt_mode; (void)rfbb_dc_upd_only; (void)rx_gain_swp;
    (void)rxrf_dc; (void)rxbb_dc;
    /* TODO(ground-truth): 467B RX-gain memory writer. Backbone: memcpy
     * staging, index math (muluh /6 lane), bit-extract loop, per-gain
     * table hook +? call, DC table stores. Reconstruct from disasm
     * .text.wr_rx_gain_mem + DWARF lines phy_chip_v7.c:657+. */
}
/* ---- static (DWARF-only, no funcdb GLOBAL) ---- */
/* set_xpd_sar phy_chip_v7.c:4238 @ phy_chip_v7.o (static) [dwarf-sig]
 * Calls: esp_dport_access_reg_read | MMIO: 0x3ff4880c, 0x3ff5d040
 * Fidelity: low - signature only */
static void set_xpd_sar(bool on)
{
    (void)on;
    /* TODO */
}

/* Undefined refs (83): __divdi3, bb_bss_cbw40_ana, bt_tx_pwctrl_init, btpwr_atten_offset, btpwr_tsen_init, btpwr_tsen_old, chan_to_freq, chip_v7_set_chan, chip_v7_set_chan_ana, chip_v7_set_chan_nomac, chip_v7_set_chan_offset, correct_rf_ana_gain_new, esp_dport_access_reg_read, ets_delay_us, force_tx_gain_en, force_txrx_off, force_txrxoff, get_phy_target_power, get_rfrx_dcap_bt, memcpy, pbus_rx_dco_cal_1step, phy_bt_ifs_set, phy_bt_power_track_en, phy_chan_gain_table, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_enter_critical, phy_exit_critical, phy_freq_correct_opt, phy_freq_wifi_only, phy_get_romfuncs, phy_i2c_init, phy_in_vdd33_offset, phy_printf, phy_set_bbfreq_init, phy_tx_pwr_error, ram_chip_i2c_readReg, ram_chip_i2c_writeReg, ram_dc_iq_est, ram_en_pwdet, ram_get_fm_sar_dout, ram_get_rf_gain_qdb, ram_index_to_txbbgain, ram_iq_est_disable, ram_iq_est_enable, ram_meas_tone_pwr_db, ram_pbus_debugmode, ram_pbus_force_mode, ram_pbus_force_test, ram_pbus_rx_dco_cal, ram_pbus_xpd_tx_on, ram_phy_get_vdd33, ram_read_sar_dout, ram_restart_cal, ram_rfcal_pwrctrl, ram_rfcal_txcap, ram_rfpll_reset, ram_rfpll_set_freq, ram_set_chan_cal_interp, ram_set_txcap_reg... */