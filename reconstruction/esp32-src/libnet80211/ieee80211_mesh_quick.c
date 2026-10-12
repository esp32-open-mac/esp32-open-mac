/* ieee80211_mesh_quick.c - reconstructed from ieee80211_mesh_quick.o (9636 bytes on disk).
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

extern int chm_is_at_home_channel();  /* external, prototype unknown */
extern int esp_wifi_internal_set_msdu_lifetime();  /* external, prototype unknown */
extern int esp_wifi_internal_set_retry_counter();  /* external, prototype unknown */
extern int ic_tx_pkt();  /* external, prototype unknown */
extern int ieee80211_getmgtframe();  /* external, prototype unknown */
extern int ieee80211_init_mesh_assoc_ie();  /* external, prototype unknown */
extern int ieee80211_recv_action_register();  /* external, prototype unknown */
extern int ieee80211_send_setup();  /* external, prototype unknown */
extern int ieee80211_set_tx_desc();  /* external, prototype unknown */
extern int mac_last_rxbuf_deinit();  /* external, prototype unknown */
extern int mac_last_rxbuf_init();  /* external, prototype unknown */
extern int pp_register_tx_cb();  /* external, prototype unknown */
extern int pp_unregister_tx_cb();  /* external, prototype unknown */
extern int wDev_Mesh_Disable_Tsf();  /* external, prototype unknown */
extern int wDev_Mesh_Enable_Tsf();  /* external, prototype unknown */
extern int wifi_get_macaddr();  /* external, prototype unknown */

int ieee80211_public_action_recv_mesh_awake(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_mesh_quick_init(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_mesh_quick_deinit(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_vnd_mesh_update_beacon(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_vnd_mesh_fully_associated(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int is_esp_mesh_assoc(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_public_action_send_mesh_awake(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* ieee80211_public_action_recv_mesh_awake @ ieee80211_mesh_quick.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: esp_mesh_quick_funcs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_public_action_recv_mesh_awake(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a4, a5 */
    /* struct offsets touched: 172 */
    /* immediates: -1, -5, 5, 0 */
    /* branches: +0xf beqz.n->0x1A */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_mesh_quick_init @ ieee80211_mesh_quick.o 00000054 size 354B bind GLOBAL
 * Calls: pp_register_tx_cb, memset, memcpy, ieee80211_init_mesh_assoc_ie, esp_wifi_internal_set_msdu_lifetime, esp_wifi_internal_set_retry_counter, wDev_Mesh_Enable_Tsf, mac_last_rxbuf_deinit, ieee80211_recv_action_register | Data refs: g_ic, ieee80211_hostapd_data_txcb, g_osi_funcs_p, .rodata.ieee80211_mesh_quick_init.str1.1, g_wifi_global_lock, esp_mesh_appie, g_mesh_init_ps_type, esp_mesh_ps_duty, ieee80211_public_action_recv_mesh_awake, g_mesh_is_started
 * Fidelity: medium - small frame, 9 calls + 6 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int ieee80211_mesh_quick_init(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 14, 28, 29, 30, 37, 44, 64, 84, 88, 116, 376 */
    /* immediates: 1, 0, 10, 11, 73, 58, 6, 8, -120, 2, 71, 0x200 */
    /* branches: +0x67 bnez->0x154; +0x6d bnez->0x154; +0x76 bnez->0x160; +0xa4 beqz->0x15D; +0x1a4 j->0x160 [loop]; +0x1ab j->0x160 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    pp_register_tx_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    ieee80211_init_mesh_assoc_ie(0, 0, 0, 0, 0, 0);  /* ordered call */
    esp_wifi_internal_set_msdu_lifetime(0, 0, 0, 0, 0, 0);  /* ordered call */
    esp_wifi_internal_set_retry_counter(0, 0, 0, 0, 0, 0);  /* ordered call */
    wDev_Mesh_Enable_Tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    mac_last_rxbuf_deinit(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_recv_action_register(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_mesh_quick_deinit @ ieee80211_mesh_quick.o 00000024 size 145B bind GLOBAL
 * Calls: wDev_Mesh_Disable_Tsf, mac_last_rxbuf_init, pp_unregister_tx_cb | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p, esp_mesh_appie, g_mesh_is_started
 * Fidelity: medium - small frame, 3 calls + 3 branch(es) mapped */
int ieee80211_mesh_quick_deinit(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a6 */
    /* struct offsets touched: 30, 84, 88, 116, 176 */
    /* immediates: 1, 0, 10, 11, 0x102 */
    /* branches: +0x39 bnez->0x8C; +0x3f bnez->0x8C; +0xab j->0x8F [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wDev_Mesh_Disable_Tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    mac_last_rxbuf_init(0, 0, 0, 0, 0, 0);  /* ordered call */
    pp_unregister_tx_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_vnd_mesh_update_beacon @ ieee80211_mesh_quick.o 0000000c size 62B bind GLOBAL
 * Calls: none | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic
 * Fidelity: medium - small frame, 0 calls + 2 branch(es) mapped */
int ieee80211_vnd_mesh_update_beacon(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 30, 84, 88 */
    /* immediates: 1 */
    /* branches: +0x12 beqz.n->0x19; +0x33 beqz.n->0x3C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_vnd_mesh_fully_associated @ ieee80211_mesh_quick.o 00000008 size 57B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - small frame, 0 calls + 5 branch(es) mapped */
int ieee80211_vnd_mesh_fully_associated(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 20, 240, 246 */
    /* immediates: 0, 1, 4 */
    /* branches: +0x22 j->0x28; +0x25 beqz.n->0x26; +0x2a beqz.n->0x26 [loop]; +0x30 bne->0x1D [loop]; +0x36 bge->0x34 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* is_esp_mesh_assoc @ ieee80211_mesh_quick.o 00000010 size 201B bind GLOBAL
 * Calls: none | Data refs: g_mesh_topology, g_mesh_init_ps_type
 * Fidelity: medium - branchy but loop-free, no direct calls; branch inventory + data refs mapped (verified against section disasm; predicates opaque) */
int is_esp_mesh_assoc(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 2, -69, 1 */
    /* branches: +0x1f bnei->0x70; +0x22 bgeui->0x18 [loop]; +0x25 j->0xC7; +0x53 beq->0xC5; +0x56 bltui->0xC5; +0x7d j->0xC7; +0x80 bltui->0xC7; +0xa8 bne->0xC5; +0xab bltui->0xC5; +0xd2 j->0xC7 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_public_action_send_mesh_awake @ ieee80211_mesh_quick.o 00000034 size 344B bind GLOBAL
 * Calls: memcpy, wifi_get_macaddr, ieee80211_getmgtframe, ieee80211_send_setup, ieee80211_set_tx_desc, chm_is_at_home_channel, ic_tx_pkt | Data refs: esp_mesh_quick_funcs, g_ic, .rodata.ieee80211_mesh_quick_init.str1.1, .rodata.ieee80211_public_action_send_mesh_a~
 * Fidelity: medium - small frame, 7 calls + 5 branch(es) mapped */
int ieee80211_public_action_send_mesh_awake(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a7 */
    /* struct offsets touched: 16, 20, 22, 28, 32, 36, 168, 228 */
    /* immediates: -1, 22, 6, 0, 16, 60, 24, 28, 4, 2, 9, 5 */
    /* branches: +0x40 bnez.n->0x14 [loop]; +0x44 j->0x156; +0x50 beqz->0xE [loop]; +0x9b beq->0xE [loop]; +0x17f beq->0x156 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    wifi_get_macaddr(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_getmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_send_setup(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_tx_desc(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_is_at_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_tx_pkt(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.ieee80211_public_action_recv_mesh_awake] "....6A.!..."+|.."
 *   [.text.ieee80211_public_action_recv_mesh_awake] ".R..@..[........"
 *   [.rodata.ieee80211_mesh_quick_init.str1.1] "......."
 *   [.text.ieee80211_mesh_quick_init] "................"
 *   [.text.ieee80211_mesh_quick_init] "................"
 *   [.text.ieee80211_mesh_quick_init] "................"
 *   [.text.ieee80211_mesh_quick_init] "................"
 *   [.text.ieee80211_mesh_quick_init] "................"
 *   [.text.ieee80211_mesh_quick_init] "....6......"a. e"
 *   [.text.ieee80211_mesh_quick_init] ".@@t` tV..0%.Vr."
 *   [.text.ieee80211_mesh_quick_init] "a...&.V........."
 *   [.text.ieee80211_mesh_quick_init] "..............."
 *   [.text.ieee80211_mesh_quick_init] ".....L.1.....(^."
 *   [.text.ieee80211_mesh_quick_init] "..}....L........"
 *   [.text.ieee80211_mesh_quick_init] ".<.............."
 *   [.text.ieee80211_mesh_quick_init] "................"
 *   [.text.ieee80211_mesh_quick_init] ".......A..A..A%."
 *   [.text.ieee80211_mesh_quick_init] "A,. .. ........."
 *   [.text.ieee80211_mesh_quick_init] "A...)...Lt...rf."
 *   [.text.ieee80211_mesh_quick_init] "b..BW.RF.. .8.a."
 *   [.text.ieee80211_mesh_quick_init] ".2#..&.. ....b!."
 *   [.text.ieee80211_mesh_quick_init] "........1..y.1.."
 *   [.text.ieee80211_mesh_quick_init] ".#.2..BW.. .B..."
 *   [.text.ieee80211_mesh_quick_init] "4.0. . ........."
 *   [.text.ieee80211_mesh_quick_init] "................"
 */
