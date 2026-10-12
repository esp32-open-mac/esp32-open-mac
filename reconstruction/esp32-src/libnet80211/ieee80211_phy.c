/* ieee80211_phy.c - reconstructed from ieee80211_phy.o (10840 bytes on disk).
 * Toolchain: xtensa-esp32-elf (esp-15.2.0), ABI args a2..a7, return a2.
 * Prototypes are generic (arity unknown); bodies preserve the observed
 * call order, branch/loop skeleton, and notable immediates from disasm.
 * Data refs appear in headers only; they are NOT typed (layouts unknown).
 * funcdb v2 edges merged: Calls/Data refs start from funcdb
 * calls[]/refs[] (R_XTENSA_ASM_EXPAND/R_XTENSA_32 rela-matched),
 * plus section-local calls (.text.X+off) from disasm relocs that
 * funcdb v2 omits; call-site order is from disasm. Tags: [v2-only]
 * = in funcdb v2 but no call site found in section disasm (appended);
 * [local] = section-local target funcdb v2 omits.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern int chm_get_current_band();  /* external, prototype unknown */
extern int esp_wifi_vnd_lora_disable();  /* external, prototype unknown */
extern int esp_wifi_vnd_lora_enable();  /* external, prototype unknown */
extern int ic_trc_update_ifx_phy_mode();  /* external, prototype unknown */
extern int wDev_disable_low_rate();  /* external, prototype unknown */
extern int wDev_enable_low_rate();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */

int phymode2str(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_phy_deinit(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_phy_type_get(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_phy_mode_show(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_setup_ratetable(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_phy_init(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_set_user_sup_rate(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* phymode2str @ ieee80211_phy.o 00000028 size 76B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.phymode2str.str1.1, .rodata.phymode2str, .rodata_wlog_warning.2
 * Fidelity: medium - small frame, 1 call + 7 branch(es) mapped */
int phymode2str(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 2, 4, 1 */
    /* branches: +0x2b bgeui->0x30; +0x3d j->0x4A; +0x43 j->0x4A; +0x49 j->0x4A; +0x4f j->0x4A [loop]; +0x55 j->0x4A [loop]; +0x6c j->0x4A [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_phy_deinit @ ieee80211_phy.o 00000008 size 24B bind GLOBAL
 * Calls: esp_wifi_vnd_lora_disable | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_phy_deinit(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_wifi_vnd_lora_disable(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_phy_type_get @ ieee80211_phy.o 00000000 size 80B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 8 branch(es) mapped */
int ieee80211_phy_type_get(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12, 50, 171, 172 */
    /* immediates: 6, -1, 1, 0, -5, 8, 5, 4, 3, 2 */
    /* branches: +0x6 beqi->0x18; +0xb beqi->0x4E; +0x14 j->0x4B; +0x1d bnei->0x28; +0x25 j->0x31; +0x28 bnei->0x44; +0x36 bltu->0x44; +0x40 j->0x4B */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_phy_mode_show @ ieee80211_phy.o 00000020 size 96B bind GLOBAL
 * Calls: strcpy | Data refs: .rodata.ieee80211_phy_mode_show.str1.1, .rodata.phymode2str.str1.1
 * Fidelity: medium - small frame, 1 call + 13 branches mapped (backward-edge marks kept; predicates opaque) */
int ieee80211_phy_mode_show(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 50, 138 */
    /* branches: +0x28 beqi->0x45; +0x2b bgeui->0x18 [loop]; +0x2e beqi->0x21 [loop]; +0x31 beqi->0x34; +0x34 j->0x5E; +0x3b beqi->0x58; +0x3e j->0x5E; +0x4a bnez.n->0x58; +0x4f j->0x58; +0x5d bnez.n->0x58 [loop] (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    strcpy(0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_setup_ratetable @ ieee80211_phy.o 00000038 size 305B bind GLOBAL
 * Calls: wifi_log, memcpy | Data refs: g_osi_funcs_p, .rodata_wlog_error.5, .rodata.ieee80211_setup_ratetable.str1.1, .rodata_wlog_error.6, .rodata.ieee80211_11b_table, .data.ieee80211_11a_table, .rodata.ieee80211_11g_table, g_ic
 * Fidelity: low - large/complex: 14 branches, 12 loop(s), 2 calls; skeleton only */
int ieee80211_setup_ratetable(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a5, a6 */
    /* struct offsets touched: 14, 20, 30, 105, 106, 169, 170, 171, 172, 176, 376, 436 */
    /* immediates: 212, 1, 0x101, 0x19f, 2, 32, 33, 15, 255, 0, -1, 31 */
    /* branches: +0x4e bnez.n->0x2E [loop]; +0x63 j->0x12F; +0x66 bnez.n->0x4C [loop]; +0x80 j->0x48 [loop]; +0x99 bnei->0x72 [loop]; +0xa7 j->0x88 [loop]; +0xaa bnei->0x88 [loop]; +0xbd j->0xB5 [loop]; +0xc3 bnei->0xA5 [loop]; +0xd9 j->0xB5 [loop] (+4 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_phy_init @ ieee80211_phy.o 0000003c size 250B bind GLOBAL
 * Calls: wifi_log, ieee80211_setup_ratetable, ic_trc_update_ifx_phy_mode, wDev_enable_low_rate, wDev_disable_low_rate, esp_wifi_vnd_lora_enable, esp_wifi_vnd_lora_disable | Data refs: g_ic, .rodata.ieee80211_setup_ratetable.str1.1, .rodata_wlog_error.3, g_wifi_nvs
 * Fidelity: medium - small frame, 7 calls + 19 branches mapped (backward-edge marks kept; predicates opaque) */
int ieee80211_phy_init(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a5, a6 */
    /* struct offsets touched: 16, 20, 61, 161, 164 */
    /* immediates: 0, 1, 2, 202, 6, -2 */
    /* branches: +0x49 beq->0x1C [loop]; +0x58 bnez.n->0x3A [loop]; +0x70 j->0x34 [loop]; +0x84 bnez->0xF6; +0x87 bnei->0x5C [loop]; +0x94 j->0x7C [loop]; +0xa5 bgeui->0x7C [loop]; +0xb3 j->0x85 [loop]; +0xc4 bnei->0xF6; +0xd2 bnez.n->0xA0 [loop] (+9 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_setup_ratetable(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_trc_update_ifx_phy_mode(0, 0, 0, 0, 0, 0);  /* ordered call */
    wDev_enable_low_rate(0, 0, 0, 0, 0, 0);  /* ordered call */
    wDev_disable_low_rate(0, 0, 0, 0, 0, 0);  /* ordered call */
    esp_wifi_vnd_lora_enable(0, 0, 0, 0, 0, 0);  /* ordered call */
    esp_wifi_vnd_lora_disable(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_set_user_sup_rate @ ieee80211_phy.o 00000014 size 70B bind GLOBAL
 * Calls: wifi_log, chm_get_current_band, ieee80211_setup_ratetable | Data refs: .rodata_wlog_warning.4
 * Fidelity: medium - small frame, 3 calls + 2 branch(es) mapped */
int ieee80211_set_user_sup_rate(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 104, 436 */
    /* immediates: 1, 2 */
    /* branches: +0x1c bnez.n->0x25; +0x35 j->0x44 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_current_band(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_setup_ratetable(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.rodata.phymode2str.str1.1] "Auto.11b.11bg.11"
 *   [.rodata.phymode2str.str1.1] "bgn.lr.11ax.unkn"
 *   [.rodata.phymode2str.str1.1] "own."
 *   [.text.phymode2str] "................"
 *   [.text.phymode2str] "................"
 *   [.text.phymode2str] "........6A...).."
 *   [.text.phymode2str] "..........!..F.."
 *   [.text.phymode2str] "!.....!..F..!..."
 *   [.text.phymode2str] "..!..F........,."
 *   [.text.phymode2str] "K........!.....!"
 *   [.text.phymode2str] "...."
 *   [.rodata.phymode2str] "o...:...@...F..."
 *   [.rodata.phymode2str] "L...X...X...R..."
 *   [.text.ieee80211_phy_deinit] "........6A......"
 *   [.text.ieee80211_phy_deinit] "................"
 *   [.text.ieee80211_phy_type_get] "6A...2&8..b&H?.."
 *   [.text.ieee80211_phy_type_get] "............2f.."
 *   [.text.ieee80211_phy_type_get] ""..."...f).".."."
 *   [.text.ieee80211_phy_type_get] ".  t..'9.....R.I"
 *   [.text.ieee80211_phy_type_get] "........2.).)..."
 *   [.rodata.ieee80211_phy_mode_show.str1.1] "lrb.b.lrbg.bg.lr"
 *   [.rodata.ieee80211_phy_mode_show.str1.1] "bgn.bgn."
 *   [.text.ieee80211_phy_mode_show] "................"
 *   [.text.ieee80211_phy_mode_show] "................"
 *   [.text.ieee80211_phy_mode_show] "6A...2..&89.H.&."
 */
