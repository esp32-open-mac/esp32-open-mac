/* Reconstruction of ate_test.o (librftest.a)
 * CU: ate_test.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 23 | funcdb functions: 12
 * Disasm: re/esp32-phy/disasm/librftest/ate_test.rdis
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
 * DPORT register reader; plain s32i to 0x3ffxxxxx are writes. */
static inline unsigned reg_rd(unsigned addr);
static inline void reg_wr(unsigned addr, unsigned val);
#define REG_READ(a) reg_rd(a)
#define REG_WRITE(a, v) reg_wr((a), (v))
/* Forward declarations for same-TU callees (defined later in file). */
S16 get_iq_est_snr(uint64 * get_power, uint8 shift_bits, bool print_en);
S16 linear_to_db_64bits(uint64 power_sig, uint8 frac_bits);

/* ate_rfpll_cap_sign ate_test.c:3893 @ ate_test.o size 324B [dwarf-sig]
 * Calls: chip_v7_set_chan, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, chip_v7_set_chan, ets_delay_us, g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ate_rfpll_cap_sign(bool print_en_in)
{
    (void)print_en_in;
    /* DWARF locals: uint16 cap@l3895, uint16 cap_set@l3895, sint8 i@l3896, sint8 j@l3896, uint8 cap_sign@l3897, uint8[] sign_num@l3898 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <ate_rfpll_cap_sign> (124 insns) + DWARF line rows for ate_test.c:3893.
     * Ordered callee relocs: chip_v7_set_chan, ets_delay_us, phy_printf.
     */
}

/* ate_rxdc_remain_check ate_test.c:2905 @ ate_test.o size 246B [dwarf-sig]
 * Calls: chip_v7_set_chan, esp_dport_access_reg_read | Data refs: chip_v7_set_chan, esp_dport_access_reg_read, g_phyFuns | MMIO: 0x3ff5c02c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ate_rxdc_remain_check(void)
{
    /* DWARF locals: uint8 chan@l2911, uint8 i@l2911, uint8 j@l2911, uint8 k@l2911, uint8 mem_addr@l2911, sint32[] dc_est@l2912, sint8[] dc_est_min@l2913 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <ate_rxdc_remain_check> (96 insns) + DWARF line rows for ate_test.c:2905.
     * Ordered callee relocs: chip_v7_set_chan, esp_dport_access_reg_read.
     */
}

/* freq_offset_get_pwr ate_test.c:722 @ ate_test.o size 1374B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x3, get_iq_est_snr, phy_printf, linear_to_db_64bits x4 | Data refs: .rodata.str1.4, esp_dport_access_reg_read, g_phyFuns, get_iq_est_snr, linear_to_db_64bits, phy_printf | MMIO: 0x3ff450a8, 0x3ff460b8
 * Fidelity: medium - tone/RXIQ setup RMWs, loop bound/accumulate swizzle, per-iter call order, sign-gated dB tail, remain scaling verified; hook args + funnel shift amounts approximate */
void freq_offset_get_pwr(U8 loop_bits, S16 tone_step, U8 corr_cycle_bits, uint64 * pwr_sum, S16 * rxiq_remain, bool rxiq_sign, bool print_en)
{
    /* DWARF locals: U8 loop_i@l724, uint64[] get_power@l725 */
    extern unsigned g_phyFuns[];
    u32 *hooktab = (u32 *)g_phyFuns[0];   /* l32i [g_phyFuns,0]; slots +60/+144/+148 */
    U64 scratch[7];                        /* frame get_power buffer (a1 target) */
    U32 n = 1u << (loop_bits & 31u);   /* ssl/sll funnel; sll uses SAR[4:0] */
    U32 i;
    u32 r;
    /* Tone-select: *(0x3ff450a8) = (read & ~3) | (tone_step & 3). */
    r = esp_dport_access_reg_read(0x3ff450a8u);
    *(volatile u32 *)0x3ff450a8u = (r & 0xfffffffcU) | ((u32)tone_step & 3u);
    /* RXIQ correlators: *(0x3ff460b8) = (read & 0xf0000000) | ((tone>>2)&0xffffff & 0x0fdbffff) | 0x00240000. */
    r = esp_dport_access_reg_read(0x3ff460b8u);
    *(volatile u32 *)0x3ff460b8u =
        (r & 0xf0000000u) | ((((u32)(tone_step >> 2)) & 0x0fdbffffu) | 0x00240000u);
    /* (Dead ssl/sll by loop_bits here; result unused - omitted.) */
    for (i = 0; i < 14; i++)
        ((u32 *)pwr_sum)[i] = 0;
    ((void (*)(u32))hooktab[15])(1);   /* prologue hook, slot +60 */
    if (n >= 1) {
        i = 0;
        do {
            U64 *acc = (U64 *)pwr_sum, *s = scratch;
            ((void (*)(u32, u32))hooktab[81])(1, (U32)((1u << corr_cycle_bits) & 0xffffu));  /* slot +0x144 */
            get_iq_est_snr(scratch, corr_cycle_bits, print_en);
            /* 7-lane u64 accumulate-with-carry; first two lanes swizzled
             * (p[0]+=s[1], p[1]+=s[0], then straight). Exact per disasm. */
            acc[0] += s[1]; acc[1] += s[0]; acc[2] += s[2]; acc[3] += s[3];
            acc[4] += s[4]; acc[5] += s[5]; acc[6] += s[6];
            ((void (*)(void))hooktab[82])();   /* slot +0x148; no arg setup */
            if (print_en)
                phy_printf("step=%d, %d\n", i, tone_step);
            i++;
        } while (i < n);
    }
    /* Funnel normalization (barrel-shift OR/movnez chains keyed by loop_bits;
     * exact per-word shift distribution approximate): average the sums. */
    for (i = 0; i < 7; i++)
        ((U64 *)pwr_sum)[i] >>= loop_bits;
    {
        /* rxiq_sign selects the dB operand order (both lanes call
         * linear_to_db_64bits twice over accumulated temps). */
        S16 db_a = linear_to_db_64bits(((U64 *)pwr_sum)[0], 3);
        S16 db_b = linear_to_db_64bits(((U64 *)pwr_sum)[1], 3);
        S16 snr = rxiq_sign ? (S16)(db_a - db_b) : (S16)(db_b - db_a);
        *rxiq_remain = (S16)((snr + 8) >> 4);   /* addi 8, srai 4, s16i */
    }
    r = esp_dport_access_reg_read(0x3ff460b8u);
    *(volatile u32 *)0x3ff460b8u = r & 0xfffbffffu;   /* clear bit 18 */
    ((void (*)(void))hooktab[15])();   /* epilogue hook, slot +60; no arg setup */
}

/* get_corr_power ate_test.c:776 @ ate_test.o size 228B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff46080, 0x3ff46084, 0x3ff46088, 0x3ff4608c, 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_corr_power(int * power, U8 shift_bits, bool print_en)
{
    (void)power;
    (void)shift_bits;
    (void)print_en;
    /* DWARF locals: int sig_i@l778, int sig_q@l778, int dc_i@l778, int dc_q@l778, sint64 temp_power@l779 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <get_corr_power> (82 insns) + DWARF line rows for ate_test.c:776.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* get_iq_est_snr ate_test.c:621 @ ate_test.o size 1324B [dwarf-sig]
 * Calls: esp_dport_access_reg_read x19, __divdi3 x8, phy_printf, linear_to_db_64bits x2 | Data refs: .rodata.str1.4, __divdi3, esp_dport_access_reg_read, linear_to_db_64bits, phy_printf | MMIO: 0x3ff46080, 0x3ff46084, 0x3ff46088, 0x3ff4608c, 0x3ff460cc, 0x3ff460d0, 0x3ff460d4, 0x3ff460d8, 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: medium - 8 quotient blocks (exact read pairs, add/sub order, div scale), 64-bit square-accumulate chains with carry, get_power slots, shift normalization, print gate, dB-diff return verified; cross-term routing into named powers approximate */
S16 get_iq_est_snr(uint64 * get_power, uint8 shift_bits, bool print_en)
{
    /* DWARF locals: sint64 sig1_i@l623, sint64 sig1_q@l623, sint64 sig2_i@l623, sint64 sig2_q@l623, sint64 sig12_i@l623, sint64 sig12_q@l623, sint64 dc_i@l623, sint64 dc_q@l623, uint64 sig_power@l624, uint64 dc_power@l624, uint64 total_power@l624, sint64 noise_power@l625, const int32 cw_rms@l626, uint8 pwr_lshift@l630 */
    /* Each quotient: q = __divdi3((sint64)(ra +/- rb) << 14, 0x7fe03).
     * (divisor-hi pool literal unresolved; treated as 0.) Reads are
     * sequenced as in the disasm (order-sensitive MMIO). */
    u32 r80 = REG_READ(0x3ff46080u);
    u32 r8c = REG_READ(0x3ff4608cu);
    S64 sig1_i = __divdi3(((S64)(S32)(r80 + r8c) << 14), 0x7fe03);
    u32 r84 = REG_READ(0x3ff46084u);
    u32 r88 = REG_READ(0x3ff46088u);
    S64 sig1_q = __divdi3(((S64)(S32)(r84 - r88) << 14), 0x7fe03);
    u32 rcc = REG_READ(0x3ff460ccu);
    u32 rd8 = REG_READ(0x3ff460d8u);
    S64 sig2_i = __divdi3(((S64)(S32)(rcc + rd8) << 14), 0x7fe03);
    u32 rd0 = REG_READ(0x3ff460d0u);
    u32 rd4 = REG_READ(0x3ff460d4u);
    S64 sig2_q = __divdi3(((S64)(S32)(rd0 - rd4) << 14), 0x7fe03);
    /* Round 2 re-reads the same pairs with sum/diff swapped (first addr via
     * preserved a5 = 0x3ff46080; verified: no a5 rewrite in range). */
    r80 = REG_READ(0x3ff46080u);
    r8c = REG_READ(0x3ff4608cu);
    S64 sig12_i = __divdi3(((S64)(S32)(r80 - r8c) << 14), 0x7fe03);
    r84 = REG_READ(0x3ff46084u);
    r88 = REG_READ(0x3ff46088u);
    S64 sig12_q = __divdi3(((S64)(S32)(r84 + r88) << 14), 0x7fe03);
    rcc = REG_READ(0x3ff460ccu);
    rd8 = REG_READ(0x3ff460d8u);
    S64 dc_i = __divdi3(((S64)(S32)(rcc - rd8) << 14), 0x7fe03);
    rd0 = REG_READ(0x3ff460d0u);
    rd4 = REG_READ(0x3ff460d4u);
    S64 dc_q = __divdi3(((S64)(S32)(rd0 + rd4) << 14), 0x7fe03);
    /* 64-bit sum-of-squares accumulations (mull/muluh/addx2 + bltu carry
     * chains). Exact term routing into the four powers is approximate; the
     * operations below preserve the verified shape: full 64-bit squares of
     * the quotients accumulated with end-around carry. */
    U64 sig_power = (U64)(sig1_i * sig1_i) + (U64)(sig1_q * sig1_q)
        + (U64)(sig2_i * sig2_i) + (U64)(sig2_q * sig2_q);
    U64 dc_power = (U64)(sig12_i * sig12_i) + (U64)(sig12_q * sig12_q)
        + (U64)(dc_i * dc_i) + (U64)(dc_q * dc_q);
    U64 total_power = sig_power + dc_power;
    U64 noise_power = total_power - sig_power;   /* r12/ppu residual lane; approximate */
    get_power[4] = sig_power;    /* words +32/+36 lane */
    get_power[3] = dc_power;     /* words +24/+28 lane */
    get_power[5] = total_power;  /* words +40/+44 lane */
    get_power[6] = noise_power;  /* words +48/+52 lane */
    /* Final power terms from 0x3ff460dc/0xe0/0xe4 (srai 4, square, accumulate
     * with carry) folded into the accumulators above [approximate]. */
    {
        S32 a = (S32)REG_READ(0x3ff460dcu) >> 4;
        S32 b = (S32)REG_READ(0x3ff460e0u) >> 4;
        total_power += (U64)(S64)(a * a) + (U64)(S64)(b * b);
        (void)REG_READ(0x3ff460e4u);   /* srli-1/shift-funnel source */
    }
    /* Barrel-shifter normalization keyed by shift_bits (ssr/ssl/srl/sra +
     * movnez funnel; exact shift amounts approximate). */
    total_power >>= (shift_bits + 7) & 63;
    sig_power >>= (shift_bits + 7) & 63;
    dc_power >>= (shift_bits + 7) & 63;
    noise_power >>= (shift_bits + 7) & 63;
    get_power[0] = total_power;   /* words +0/+4 lane */
    get_power[1] = sig_power;     /* words +8/+12 lane */
    get_power[2] = dc_power;      /* words +16/+20 lane */
    if (print_en)
        phy_printf("total_power=%lld, sig_power=%lld, dc_power=%lld, noise_power=%lld\n",
            total_power, sig_power, dc_power, (S64)noise_power);
    {
        S16 db_sig = linear_to_db_64bits(sig_power, 3);
        S16 db_n = linear_to_db_64bits(noise_power, 3);
        return (S16)((S32)(db_sig - db_n) << 16 >> 16);   /* sub + sext 15 */
    }
}

/* linear_to_db_64bits ate_test.c:598 @ ate_test.o size 287B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S16 linear_to_db_64bits(uint64 power_sig, uint8 frac_bits)
{
    (void)power_sig;
    (void)frac_bits;
    /* DWARF locals: U8[] db_table@l600, int8 maxbit@l601, uint8 sig_ind@l602, uint8 i@l602 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <linear_to_db_64bits> (104 insns) + DWARF line rows for ate_test.c:598.
     * Ordered callee relocs: memcpy.
     */
}

/* module_test_cal_print ate_test.c:148 @ ate_test.o size 1126B [dwarf-sig]
 * Calls: phy_get_rf_cal_version, phy_printf x57, esp_dport_access_reg_read x2 | Data refs: .rodata.str1.4, chip7_sleep_params, esp_dport_access_reg_read, noise_array, phy_get_rf_cal_version, phy_printf, phy_rxbb_dc, phy_rxrf_dc, tx_rf_ana_gain | MMIO: 0x3ff5a004, 0x3ff5a008
 * Fidelity: medium-high - print order, all 57 format strings (exact per .rodata.str1.4), loop bounds/steps, field-decode clamps verified per disasm; redundant print_en gates folded */
void module_test_cal_print(bool print_en)
{
    /* DWARF locals: uint8 i@l150, sint32 temp@l151, s8 iq_mg@l152, s8 iq_mp@l152, u32 loop_i@l153, uint16 * txdc@l154, sint16[] rxdc@l155, u8 rfrx_index@l156, u16 bbgain@l157, u32 vdd33@l164, s8 vdd33_offset@l165, u8 temp_code@l166, uint16 i_m@l397 */
    extern U8 chip7_sleep_params[];   /* byte table; word/halfword views below */
    extern U16 tx_rf_ana_gain[];      /* l16ui pair */
    extern S16 noise_array[];         /* l16si, 3 entries */
    extern u32 phy_rxrf_dc[];         /* l32i words */
    extern u32 phy_rxbb_dc[];         /* l32i words */
    u32 *chipw = (u32 *)chip7_sleep_params;
    U16 *chiph = (U16 *)chip7_sleep_params;
    S16 *chipsh = (S16 *)chip7_sleep_params;
    S8 *chipc = (S8 *)chip7_sleep_params;
    U8 *chipb = chip7_sleep_params;
    u32 w, vdd33;
    int i, k;
    if (!print_en)
        return;   /* disasm: beqz -> tail stub; all prints gated, loops side-effect free */
    phy_printf("phy_version: %d, %s, %s, %s\n", phy_get_rf_cal_version(), "a3a4459", "Oct 28 2025", "14:30:12");
    {
        u32 e08 = esp_dport_access_reg_read(0x3ff5a008u);
        u32 e04 = esp_dport_access_reg_read(0x3ff5a004u);
        phy_printf("CHIP_ID: 0x%x, 0x%x\n\n", e08, e04);
    }
    phy_printf("param_flag: 0x%x\n", chipw[0]);
    w = chipw[48];   /* l32i +192 */
    vdd33 = (w >> 16) & 0xffffu;
    phy_printf("vdd33=%d, temp_code=%d, offset=%d\n", vdd33, w & 0xffu, (S8)(w >> 8));
    phy_printf("rc_dout, %d; wifi: %d, %d, %d, %d, bt: %d, %d\n",
        chipb[80], chipb[84], chipb[85], chipb[86], chipb[87], chipb[88], chipb[89]);
    phy_printf("cal_rf_ana_gain, rf_gain=0x%x, ana_gain=0x%x\n", tx_rf_ana_gain[1], tx_rf_ana_gain[0]);
    for (i = 0; i < 3; i++)   /* noise_array..+6 step 2 */
        phy_printf("RX_NOISEFLOOR, %d\n", noise_array[i]);
    phy_printf("TXCAP_TMX2G_CCT_LOAD, ");
    for (i = 0; i < 4; i++)   /* chip7..+0xc step 3 */
        phy_printf("%d, ", chipb[64 + 3 * i]);
    phy_printf("\n");
    phy_printf("TXCAP_PA2G_CCT_STG1, ");
    for (i = 0; i < 4; i++)
        phy_printf("%d, ", chipb[65 + 3 * i]);
    phy_printf("\n");
    phy_printf("TXCAP_PA2G_CCT_STG2, ");
    for (i = 0; i < 4; i++)
        phy_printf("%d, ", chipb[66 + 3 * i]);
    phy_printf("\n");
    phy_printf("TX_POWER_BACKOFF, ");
    for (i = 0; i < 4; i++)   /* l16si [a6+4], chip7..+0x8 step 2 */
        phy_printf("%d, ", chipsh[2 + i]);
    phy_printf("\n");
    phy_printf("TX_PWRCTRL_ATTEN, ");
    for (i = 0; i < 24; i++)  /* chip7+0x60..+0x78 step 1 */
        phy_printf("%d, ", chipc[0x60 + i]);
    phy_printf("\n");
    phy_printf("TXIQ,");
    for (i = 0; i < 2; i++) { /* l16ui [a8+52], chip7..+0x4 step 2 */
        u32 f1 = (chiph[26 + i] >> 6) & 0x1fu, f0 = chiph[26 + i] & 0x3fu;
        u32 d1 = f1 <= 15 ? f1 : ((f1 - 32) & 0xffu);   /* bge 15 -> keep */
        u32 d0 = f0 <= 31 ? f0 : ((f0 - 64) & 0xffu);   /* bge 31 -> keep */
        phy_printf("%d, %d; ", (S8)d1, (S8)d0);
    }
    phy_printf("\n");
    phy_printf("TXDC, ");
    for (k = 0; k < 5; k++) { /* chip7..+0x28 step 8; l16ui +12..+18 */
        U8 *p = chipb + 8 * k;
        phy_printf("%d, %d, %d, %d; ",
            ((U16 *)(p + 12))[0], ((U16 *)(p + 14))[0],
            ((U16 *)(p + 16))[0], ((U16 *)(p + 18))[0]);
    }
    phy_printf("\n");
    phy_printf("BT_PA_GAIN, ");
    for (i = 0; i < 8; i++)   /* l8ui [a6+120], chip7..+0x8 step 1 */
        phy_printf("0x%x, ", chipb[120 + i]);
    phy_printf("\n");
    phy_printf("BT_DIG_ATTEN, ");
    for (i = 0; i < 8; i++)   /* l8ui [a6+129] */
        phy_printf("%d, ", (S8)chipb[129 + i]);
    phy_printf("\n");
    phy_printf("BT_TX_BB, 0x%x\n", chiph[72]);   /* l16ui [a7+144], a7=chip7 */
    phy_printf("delta_bt_atten, ");
    for (i = 0; i < 5; i++)   /* l8ui [a5+139], chip7..+0x5 step 1 */
        phy_printf("%d, ", (S8)chipb[139 + i]);
    phy_printf("\n");
    phy_printf("BT_TXIQ,");
    for (i = 0; i < 3; i++) { /* l16ui [a5+144], chip7..+0x6 step 2 */
        u32 f1 = (chiph[72 + i] >> 6) & 0x1fu, f0 = chiph[72 + i] & 0x3fu;
        u32 d1 = f1 <= 15 ? f1 : ((f1 - 32) & 0xffu);
        u32 d0 = f0 <= 31 ? f0 : ((f0 - 64) & 0xffu);
        phy_printf("%d, %d; ", (S8)d1, (S8)d0);
    }
    phy_printf("\n");
    phy_printf("BT_TXDC, ");
    for (k = 0; k < 3; k++) { /* chip7..+0x18 step 8; l16ui +152..+158 */
        U8 *p = chipb + 8 * k;
        phy_printf("%d, %d, %d, %d; ",
            ((U16 *)(p + 152))[0], ((U16 *)(p + 154))[0],
            ((U16 *)(p + 156))[0], ((U16 *)(p + 158))[0]);
    }
    phy_printf("\n");
    phy_printf("RXIQ, ");
    for (i = 0; i < 4; i++) { /* l16ui [a3+56], chip7..+0x8 step 2 */
        u32 f1 = (chiph[28 + i] >> 6) & 0x1fu, f0 = chiph[28 + i] & 0x3fu;
        u32 d1 = f1 <= 15 ? f1 : ((f1 - 32) & 0xffu);
        u32 d0 = f0 <= 31 ? f0 : ((f0 - 64) & 0xffu);
        phy_printf("%d, %d; ", (S8)d1, (S8)d0);
    }
    phy_printf("\n");
    phy_printf("RXDC_RFRX_BT, ");
    for (i = 0; i < 9; i++) { /* phy_rxrf_dc..+0x24 step 4 */
        u32 v = phy_rxrf_dc[i];
        phy_printf("%d, %d; ", (S32)v >> 16, (S16)v);
    }
    phy_printf("\n");
    phy_printf("RXDC_RFRX_WIFI, ");
    for (i = 9; i < 34; i++) { /* phy_rxrf_dc+0x24..+0x88 step 4; zero -> 0x100 pair */
        u32 v = phy_rxrf_dc[i];
        u32 hi = 0x100u, lo = 0x100u;
        if (v != 0) { hi = v >> 16; lo = (u32)(S16)v; }
        phy_printf("%d, %d; ", hi, lo);
    }
    phy_printf("\n");
    phy_printf("RXDC_RXBB_WIFI, ");
    for (i = 0; i < 4; i++) { /* phy_rxbb_dc..+0x10 step 4 */
        u32 v = phy_rxbb_dc[i];
        phy_printf("%d, %d; ", v >> 16, (S32)(S16)v);
    }
    phy_printf("\n");
    phy_printf("TX_VDD33=%d\n", vdd33);
}

/* rxspur_test ate_test.c:3840 @ ate_test.o size 234B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, rx_spur_cal, get_spur4m_pwr, phy_printf | Data refs: .rodata.str1.4, chip7_phy_init_ctrl, g_phyFuns, get_spur4m_pwr, phy_printf, rx_spur_cal, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rxspur_test(bool print_en)
{
    (void)print_en;
    /* DWARF locals: uint8 set_dac1@l3847, uint8 dac_org@l3847, uint8 dcur_org@l3847, uint8 i@l3847, uint8 data@l3847, uint32[] rx_pwr1@l3848, uint32[] rx_pwr2@l3848 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <rxspur_test> (95 insns) + DWARF line rows for ate_test.c:3840.
     * Ordered callee relocs: set_chan_freq_sw_start, rx_spur_cal, get_spur4m_pwr, phy_printf.
     */
}

/* test_set_rf_freq_offset ate_test.c:796 @ ate_test.o size 82B [dwarf-sig]
 * Calls: chip_v7_rxmax_ext_ana | Data refs: chip_v7_rxmax_ext_ana, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_set_rf_freq_offset(uint8 crystal_select, uint16 freq, sint16 freq_offset)
{
    (void)crystal_select;
    (void)freq;
    (void)freq_offset;
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <test_set_rf_freq_offset> (33 insns) + DWARF line rows for ate_test.c:796.
     * Ordered callee relocs: chip_v7_rxmax_ext_ana.
     */
}

/* txdc_delta_max ate_test.c:3761 @ ate_test.o size 123B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void txdc_delta_max(sint16 * delta, sint16 * delta_max)
{
    (void)delta;
    (void)delta_max;
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <txdc_delta_max> (44 insns) + DWARF line rows for ate_test.c:3761.
     */
}

/* txdc_stable_sub ate_test.c:3776 @ ate_test.o size 197B [dwarf-sig]
 * Calls: ets_delay_us, txdc_delta_max | Data refs: ets_delay_us, g_phyFuns, txdc_delta_max | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void txdc_stable_sub(bool bt_mode, sint16 * txdc)
{
    (void)bt_mode;
    (void)txdc;
    /* DWARF locals: uint8 i@l3778, uint8 max_i@l3778, sint16[] txdc_cal@l3779, sint16[] txdc_0@l3779, sint16[] delta@l3780, sint16[] delta_max@l3780 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <txdc_stable_sub> (74 insns) + DWARF line rows for ate_test.c:3776.
     * Ordered callee relocs: ets_delay_us, txdc_delta_max.
     */
}

/* txdc_stable_test ate_test.c:3807 @ ate_test.o size 71B [dwarf-sig]
 * Calls: txdc_stable_sub, txdc_delta_max, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, ets_delay_us, phy_printf, txdc_delta_max, txdc_stable_sub | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void txdc_stable_test(bool print_en)
{
    (void)print_en;
    /* DWARF locals: uint8 i@l3814, uint8 num@l3814, sint16[] dc_delta@l3815, sint16[] delta_max@l3815 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <txdc_stable_test> (27 insns) + DWARF line rows for ate_test.c:3807.
     * Ordered callee relocs: txdc_stable_sub, txdc_delta_max, ets_delay_us, phy_printf.
     */
}

/* Undefined refs (18): __divdi3, chip7_phy_init_ctrl, chip7_sleep_params, chip_v7_rxmax_ext_ana, chip_v7_set_chan, esp_dport_access_reg_read, ets_delay_us, g_phyFuns, get_spur4m_pwr, memcpy, noise_array, phy_get_rf_cal_version, phy_printf, phy_rxbb_dc, phy_rxrf_dc, rx_spur_cal, set_chan_freq_sw_start, tx_rf_ana_gain */