/* ieee80211_regdomain.c - reconstructed from ieee80211_regdomain.o (15420 bytes on disk).
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

extern int chm_check_channel_is_valid();  /* external, prototype unknown */
extern int chm_get_band_from_chan();  /* external, prototype unknown */
extern int chm_get_current_band();  /* external, prototype unknown */
extern int phy_get_most_tpw();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */

int ieee80211_regdomain_max_tx_power(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_get_country(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_update_phy_country(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_update(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_update_in_scan(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_update_in_connect(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_add_countryie(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_max_chan(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_ap_max_chan(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_min_chan(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_ap_min_chan(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_chan_num(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_policy(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_chan_in_range(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_check_channel(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_check_ap_channel(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_is_active_scan(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_get_regdomain(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int get_channel_max_bandwidth(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_is_40mhz_valid_bw(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_regdomain_get_country_info(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* ieee80211_regdomain_max_tx_power @ ieee80211_regdomain.o 00000008 size 50B bind GLOBAL
 * Calls: phy_get_most_tpw | Data refs: s_map
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
int ieee80211_regdomain_max_tx_power(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 12, 1, 2, 20 */
    /* branches: +0x26 blt->0x2A; +0x2f j->0x30 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    phy_get_most_tpw(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_get_country @ ieee80211_regdomain.o 00000008 size 54B bind GLOBAL
 * Calls: chm_get_band_from_chan[v2-only], ieee80211_get_regdomain[v2-only] | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - small frame, 2 calls + 5 branch(es) mapped */
int ieee80211_regdomain_get_country(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12, 16, 152, 175, 228 */
    /* immediates: 0x404, 0x2ac */
    /* branches: +0x1a bnez.n->0x34; +0x21 beqz.n->0x34; +0x26 bnei->0x34; +0x2c beqz.n->0x34; +0x34 beqz.n->0x34 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_band_from_chan(0, 0, 0, 0, 0, 0);  /* ordered call [v2-only] */
    ieee80211_get_regdomain(0, 0, 0, 0, 0, 0);  /* ordered call [v2-only] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_update_phy_country @ ieee80211_regdomain.o 0000000c size 36B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_update_phy_country(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 224, 237 */
    /* immediates: 0 */
    /* branches: +0x18 bltui->0x20 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_update @ ieee80211_regdomain.o 00000028 size 352B bind GLOBAL
 * Calls: chm_get_current_band, memset, memcmp, ieee80211_update_phy_country, memcpy, ieee80211_regdomain_update[v2-only] | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - small frame, 6 calls + 19 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int ieee80211_regdomain_update(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a4, a5, a6, a7 */
    /* struct offsets touched: 12, 16, 20, 24, 28, 30, 152 */
    /* immediates: 0, 1, -1, -3, 12, 14, 15, 3, 0x404 */
    /* branches: +0x4a beq->0x28 [loop]; +0x4d bne->0x2D [loop]; +0x52 j->0x15E; +0x72 bgeui->0x50 [loop]; +0x7b bnez->0x28 [loop]; +0xc1 j->0xBA [loop]; +0xc4 bnei->0xB8 [loop]; +0xca bltu->0xB8 [loop]; +0xd2 blt->0xB8 [loop]; +0xe2 bne->0x9C [loop] (+9 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_current_band(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    ieee80211_update_phy_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    ieee80211_regdomain_update(0, 0, 0, 0, 0, 0);  /* ordered call [v2-only] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_update_in_scan @ ieee80211_regdomain.o 00000004 size 18B bind GLOBAL
 * Calls: ieee80211_regdomain_update | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_update_in_scan(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 80 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_update(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_update_in_connect @ ieee80211_regdomain.o 00000004 size 20B bind GLOBAL
 * Calls: ieee80211_regdomain_update | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_update_in_connect(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0x2ac */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_update(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_add_countryie @ ieee80211_regdomain.o 0000000c size 101B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country, memcmp | Data refs: .rodata.ieee80211_add_countryie.str1.1
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int ieee80211_add_countryie(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 2, 7, 6, 8 */
    /* branches: +0x24 beqz->0x60 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_max_chan @ ieee80211_regdomain.o 00000008 size 39B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_max_chan(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12 */
    /* immediates: 14, -1 */
    /* branches: +0x17 beqz->0x25 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_ap_max_chan @ ieee80211_regdomain.o 00000004 size 30B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_ap_max_chan(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: -1 */
    /* branches: +0x16 beqz.n->0x1C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_min_chan @ ieee80211_regdomain.o 00000008 size 30B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_min_chan(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12 */
    /* immediates: 1 */
    /* branches: +0x18 beqz->0x1C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_ap_min_chan @ ieee80211_regdomain.o 00000008 size 27B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_ap_min_chan(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* branches: +0x14 bnez.n->0x19 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_chan_num @ ieee80211_regdomain.o 00000008 size 30B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_chan_num(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12 */
    /* immediates: 14 */
    /* branches: +0x18 beqz->0x1C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_policy @ ieee80211_regdomain.o 00000004 size 13B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_policy(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 8 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_chan_in_range @ ieee80211_regdomain.o 0000000c size 50B bind GLOBAL
 * Calls: chm_get_band_from_chan, ieee80211_regdomain_max_chan, ieee80211_regdomain_min_chan | Data refs: none
 * Fidelity: medium - small frame, 3 calls + 2 branch(es) mapped */
int ieee80211_regdomain_chan_in_range(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* immediates: 0, 1 */
    /* branches: +0x24 bltu->0x30; +0x33 bgeu->0x2D [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_band_from_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_regdomain_max_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_regdomain_min_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_check_channel @ ieee80211_regdomain.o 00000008 size 35B bind GLOBAL
 * Calls: chm_check_channel_is_valid, ieee80211_regdomain_chan_in_range | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int ieee80211_regdomain_check_channel(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0 */
    /* branches: +0x19 beq->0x1E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_check_channel_is_valid(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_regdomain_chan_in_range(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_check_ap_channel @ ieee80211_regdomain.o 00000010 size 52B bind GLOBAL
 * Calls: chm_check_channel_is_valid, chm_get_band_from_chan, ieee80211_regdomain_ap_max_chan, ieee80211_regdomain_ap_min_chan | Data refs: none
 * Fidelity: medium - small frame, 4 calls + 3 branch(es) mapped */
int ieee80211_regdomain_check_ap_channel(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* immediates: 0 */
    /* branches: +0x20 beqz.n->0x30; +0x32 bltu->0x30 [loop]; +0x3d bgeu->0x32 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_check_channel_is_valid(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_band_from_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_regdomain_ap_max_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_regdomain_ap_min_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_is_active_scan @ ieee80211_regdomain.o 00000004 size 47B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_regdomain_is_active_scan(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12 */
    /* immediates: 0, 1, 11 */
    /* branches: +0x22 bltu->0x24 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_get_regdomain @ ieee80211_regdomain.o 0000000c size 65B bind GLOBAL
 * Calls: memcmp | Data refs: regdomain_table, regulatory_data
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int ieee80211_get_regdomain(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* immediates: 0, 35, 2, 3, 1 */
    /* branches: +0x1a j->0x37; +0x2b bnez.n->0x35; +0x3e j->0x3F; +0x46 bne->0x11 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* get_channel_max_bandwidth @ ieee80211_regdomain.o 00000010 size 146B bind GLOBAL
 * Calls: wifi_log, chm_get_band_from_chan, ieee80211_regdomain_min_chan | Data refs: .rodata_wlog_error.2
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
int get_channel_max_bandwidth(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* immediates: 2, 0, 1, 4, 14 */
    /* branches: +0x16 beqz.n->0x15 [loop]; +0x21 j->0x45; +0x34 j->0x8E; +0x43 bltu->0x45; +0x49 bltu->0x45 [loop]; +0x52 j->0x80; +0x58 bltu->0x28 [loop]; +0x5f beq->0x90; +0x73 j->0x88; +0x81 bltu->0x88 (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_band_from_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_regdomain_min_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_is_40mhz_valid_bw @ ieee80211_regdomain.o 0000000c size 42B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country, ieee80211_get_regdomain, get_channel_max_bandwidth | Data refs: none
 * Fidelity: medium - small frame, 3 calls + 2 branch(es) mapped */
int ieee80211_is_40mhz_valid_bw(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 1, 0 */
    /* branches: +0x20 beqz.n->0x28; +0x2c bgeui->0x25 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_regdomain(0, 0, 0, 0, 0, 0);  /* ordered call */
    get_channel_max_bandwidth(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_regdomain_get_country_info @ ieee80211_regdomain.o 00000008 size 139B bind GLOBAL
 * Calls: ieee80211_get_regdomain, chm_get_band_from_chan | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 5 branch(es) mapped */
int ieee80211_regdomain_get_country_info(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a5, a6, a7 */
    /* immediates: -1, 0, 1 */
    /* branches: +0x18 beqz->0x84; +0x38 j->0x7B; +0x4d bnei->0x76; +0x53 bnez->0x54; +0x86 bltu->0x34 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_get_regdomain(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_band_from_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.ieee80211_regdomain_max_tx_power] "........6A......"
 *   [.text.ieee80211_regdomain_max_tx_power] "......-...#..v.."
 *   [.text.ieee80211_regdomain_max_tx_power] ".....#.,. .."..F"
 *   [.text.ieee80211_regdomain_max_tx_power] "....+..B.."
 *   [.text.ieee80211_regdomain_get_country] "........6A.!...."
 *   [.text.ieee80211_regdomain_get_country] ""..*(....8......"
 *   [.text.ieee80211_regdomain_get_country] "H.x.(&fY..(9...."
 *   [.text.ieee80211_regdomain_get_country] ".....I".. (..."
 *   [.text.ieee80211_update_phy_country] "............6A.."
 *   [.text.ieee80211_update_phy_country] ".........(......"
 *   [.text.ieee80211_update_phy_country] ".......(8......."
 *   [.text.ieee80211_regdomain_update] "........VUUU...."
 *   [.text.ieee80211_regdomain_update] "................"
 *   [.text.ieee80211_regdomain_update] "........6..A...."
 *   [.text.ieee80211_regdomain_update] "}.H.IAA..iQXD. ."
 *   [.text.ieee80211_regdomain_update] "..........g..g.."
 *   [.text.ieee80211_regdomain_update] "...L.B.....B...."
 *   [.text.ieee80211_regdomain_update] "....@O1@..M..J.."
 *   [.text.ieee80211_regdomain_update] ".t.+.`. .D.V...."
 *   [.text.ieee80211_regdomain_update] ".....q.a. ......"
 *   [.text.ieee80211_regdomain_update] ".........a..t..."
 *   [.text.ieee80211_regdomain_update] "...A.. .......A."
 *   [.text.ieee80211_regdomain_update] ". .....q.A.. .."
 *   [.text.ieee80211_regdomain_update] ".F..f......9...."
 *   [.text.ieee80211_regdomain_update] "...,.}.b..M.iQm."
 */
