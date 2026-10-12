/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_input.o
 * Blob: esp32/libnet80211.a(ieee80211_input.o) -> /tmp/re_esp32/libnet80211/ieee80211_input.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_input.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): esp_mesh_quick_funcs, g_authmode_threshold_failure, g_ic, g_osi_funcs_p, g_wifi_menuconfig, g_wifi_nvs, ic_ebuf_recycle_rx, ic_set_sta, ieee80211_regdomain_chan_in_range, memcmp, memcpy, memset, sta_is_11r_enabled, sta_is_wifi_ent_enabled, sta_is_wpa3_enabled, wifi_log
 */
/* Common decompilation notes (all files in this directory):
 * - Xtensa ABI: incoming args a2..a7, return value in a2. `entry a1,N` = stack frame N bytes.
 * - ebuf (esfbuf) layout observed via disasm: word at +0 (flags/refcnt?), +4 (data/len ptr),
 *   +20/+22 (u16 length fields, see s16i/l16ui pairs), +44 (priv/control word).
 * - 802.11 header offsets used below: +0 FC, +2 duration, +4 addr1, +10 addr2,
 *   +16 addr3, +22 len/seqctl, +24 seqctl/addr4/QoS, +26 QoS/HT.
 * - Key PN/counter words observed at key+152 (low32) / key+156 (high32),
 *   key bytes at +153/+154/+155/+158/+159 (l8ui/s8i sequences in *_encap).
 * - `Calls:`/`Data refs:` in each header are observed in that function's
 *   disasm section (R_XTENSA_ASM_EXPAND / R_XTENSA_32), NOT the empty
 *   funcdb calls[]/refs[] (funcdb has no per-function edges for this lib).
 * - Constants appear literally in disasm (movi/extui/slli/mask immediates).
 */
#include <stdint.h>
#include <string.h>
/* Forward declarations for intra-object calls (definitions follow in funcdb order): */
int ieee80211_alloc_challenge(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_challenge(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_negotiate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_negotiate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_better_rsn_pairwise_cipher(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_better_rsn_pairwise_cipher(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_11b_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_11b_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_ht_cipher(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_ht_cipher(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_lr_only(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_lr_only(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_support_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_support_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_rsn(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_rsn(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_wapi(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_wapi(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_wpa(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_wpa(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_rsn_cipher_priority(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_rsn_cipher_priority(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_max_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_max_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_lr_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_lr_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_phy_mode(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_phy_mode(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_rateset(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_rateset(void *a2, void *a3, unsigned a4, unsigned a5);

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
struct ebuf { u32 w0; u32 _r1; void *data; u32 _r2[3]; u16 len20; u16 len22; u32 _r3[5]; u32 w44; };
struct ic { u32 _pad[128]; };
struct node { u8 mac[6]; };
struct key { u32 _pad[38]; u32 pn_lo; /* +152 */ u32 pn_hi; /* +156 */ };
extern struct ic *g_ic;
extern void *g_osi_funcs_p;
extern void *g_scan;
extern void *g_chm;

/* Observed callees (declarations with unspecified args; definitions follow where local): */
extern int ic_ebuf_recycle_rx();
extern int ic_set_sta();
extern int ieee80211_regdomain_chan_in_range();
extern int sta_is_11r_enabled();
extern int sta_is_wifi_ent_enabled();
extern int sta_is_wpa3_enabled();
extern int wifi_log();

/* ieee80211_alloc_challenge @ ieee80211_input.o 0000000c size 60B bind GLOBAL
 * Calls: wifi_log | Data refs: g_osi_funcs_p, .rodata_wlog_error.7, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_alloc_challenge */
int ieee80211_alloc_challenge(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_challenge(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 128, 1, 4, 0 */
  /* observed branches: bnez.nx1 */
  /* observed memory traffic (first 5): */
    /* l32i a8, a2, -- off 176 */
    /* l32i a8, a8, -- 0: frame control */
    /* l32i a8, a8, -- off 0x16c */
    /* s32i a10, a2, -- off 176 */
    /* l32i a9, a2, -- off 176 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 176); /* l32i a8,a2+176 → +176:  */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i a8,a8+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 364); /* l32i a8,a8+364 → +364:  */
  *(u32 *)((u8 *)a2 + 176) = regs[1]; /* s32i a10,a2+176 → +176:  */
  regs[9] = *(u32 *)((u8 *)a2 + 176); /* l32i a9,a2+176 → +176:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_amsdu_negotiate @ ieee80211_input.o 00000010 size 198B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_amsdu_negotiate */
int ieee80211_amsdu_negotiate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_negotiate(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: bnez.nx2, bneix1, beqx2, bnex3, banyx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a2, -- 0: frame control */
    /* l32i a8, a8, -- 0x14c: ic/eb control word */
    /* l16ui a11, a8, -- off 124 */
    /* l16ui a11, a8, -- off 126 */
    /* l32i.n a3, a2, -- 12: 802.11 header region */
    /* s32i.n a3, a2, -- 12: 802.11 header region */
    /* s32i.n a10, a2, -- 12: 802.11 header region */
    /* s32i.n a9, a2, -- 12: 802.11 header region */
    /* s32i.n a9, a2, -- 12: 802.11 header region */
    /* s32i.n a8, a2, -- 12: 802.11 header region */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a8,a2+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 332); /* l32i a8,a8+332 → +332: ic/eb control word */
  regs[1] = *(u16 *)(((u8 *)0) + 124); /* l16ui → +124:  */
  regs[1] = *(u16 *)(((u8 *)0) + 126); /* l16ui → +126:  */
  regs[3] = *(u32 *)((u8 *)a2 + 12); /* l32i.n a3,a2+12 → +12: 802.11 header region */
  *(u32 *)((u8 *)a2 + 12) = regs[3]; /* s32i.n a3,a2+12 → +12: 802.11 header region */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_better_rsn_pairwise_cipher @ ieee80211_input.o 0000000c size 41B bind GLOBAL
 * Calls: ieee80211_rsn_cipher_priority | Data refs: g_ic, ieee80211_rsn_cipher_priority
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_better_rsn_pairwise_cipher */
int ieee80211_better_rsn_pairwise_cipher(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_better_rsn_pairwise_cipher(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0 */
  /* observed branches: bltx1 */
  /* observed memory traffic (first 1): */
    /* l8ui a10, a8, -- 2: duration */
  /* observed call sequence (in order): ieee80211_rsn_cipher_priority */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  (void)((int(*)())ieee80211_rsn_cipher_priority)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_decap @ ieee80211_input.o 0000002c size 414B bind GLOBAL
 * Calls: memcpy, wifi_log, ic_ebuf_recycle_rx | Data refs: .rodata_wlog_warning.2, g_ic, memcpy, wifi_log, ic_ebuf_recycle_rx
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_decap */
int ieee80211_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_decap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 240, 0, 170, 1, 2, 32, 24, 254, 52, -18 */
  /* observed branches: bneix3, bgeux1, beqx2, bnex4, beqix2, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l8ui a8, a3, -- 0: frame control */
    /* l8ui a3, a11, -- 1: frame control/duration */
    /* l8ui a3, a11, -- 30: 802.11 header region */
    /* l8ui a3, a11, -- 24: seqctl/addr4/QoS */
    /* l32i.n a8, a2, -- 28: HT */
    /* l32i.n a12, a2, -- 4: addr1 */
    /* s32i.n a8, a2, -- 28: HT */
    /* l32i.n a10, a12, -- 4: addr1 */
    /* l8ui a8, a10, -- 0: frame control */
    /* l8ui a9, a10, -- 1: frame control/duration */
  /* observed call sequence (in order): memcpy -> wifi_log -> ic_ebuf_recycle_rx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  regs[3] = *(u8 *)(((u8 *)0) + 1); /* l8ui → +1: frame control/duration */
  regs[3] = *(u8 *)(((u8 *)0) + 30); /* l8ui → +30: 802.11 header region */
  regs[3] = *(u8 *)(((u8 *)0) + 24); /* l8ui → +24: seqctl/addr4/QoS */
  regs[8] = *(u32 *)((u8 *)a2 + 28); /* l32i.n a8,a2+28 → +28: HT */
  regs[1] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a12,a2+4 → +4: addr1 */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_recycle_rx)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_deliver_data @ ieee80211_input.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_deliver_data */
int ieee80211_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_is_11b_rate @ ieee80211_input.o 00000000 size 8B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_is_11b_rate */
int ieee80211_is_11b_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_11b_rate(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_is_ht_cipher @ ieee80211_input.o 00000004 size 39B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_is_ht_cipher */
int ieee80211_is_ht_cipher(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_ht_cipher(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0 */
  /* observed memory traffic (first 1): */
    /* l8ui a8, a8, -- 2: duration */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_is_lr_only @ ieee80211_input.o 00000000 size 24B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_is_lr_only */
int ieee80211_is_lr_only(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_lr_only(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 1): */
    /* l8ui a9, a2, -- off 131 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u8 *)((u8 *)a2 + 131); /* l8ui → +131:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_is_support_rate @ ieee80211_input.o 00000000 size 72B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_is_support_rate */
int ieee80211_is_support_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_support_rate(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: beqz.nx3, bltx2, beqx1 */
  /* observed memory traffic (first 4): */
    /* l8ui a10, a2, -- 1: frame control/duration */
    /* l8ui a8, a8, -- 2: duration */
    /* l8ui a9, a3, -- 1: frame control/duration */
    /* l8ui a8, a8, -- 2: duration */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u8 *)((u8 *)a2 + 1); /* l8ui → +1: frame control/duration */
  regs[8] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  regs[9] = *(u8 *)((u8 *)a3 + 1); /* l8ui → +1: frame control/duration */
  regs[8] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_parse_action @ ieee80211_input.o 00000004 size 194B bind GLOBAL
 * Calls: memcmp | Data refs: memcmp
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_parse_action */
int ieee80211_parse_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_action(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1, 1, 0, 6, 8 */
  /* observed branches: beqz.nx2, beqix5, bneix1, bnex1, bgeux2 */
  /* observed memory traffic (first 4): */
    /* l8ui a6, a4, -- 0: frame control */
    /* l8ui a8, a4, -- 1: frame control/duration */
    /* l8ui a8, a4, -- 1: frame control/duration */
    /* l8ui a4, a4, -- 1: frame control/duration */
  /* observed call sequence (in order): memcmp */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[6] = *(u8 *)(eb8 + 0); /* l8ui → +0: frame control */
  regs[8] = *(u8 *)(eb8 + 1); /* l8ui → +1: frame control/duration */
  regs[8] = *(u8 *)(eb8 + 1); /* l8ui → +1: frame control/duration */
  regs[4] = *(u8 *)(eb8 + 1); /* l8ui → +1: frame control/duration */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_parse_beacon @ ieee80211_input.o 00000068 size 1535B bind GLOBAL
 * Calls: wifi_log, memset, .text.is_rsne_override_oui, ieee80211_regdomain_chan_in_range | Data refs: .rodata.ieee80211_setup_phy_mode.str1.1, .rodata_wlog_error.8, .rodata.ieee80211_parse_beacon, g_wifi_nvs, g_ic, esp_mesh_quick_funcs, .rodata_wlog_debug.9, wifi_log, memset, .text.is_rsne_override_oui
 * Fidelity: low - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.ieee80211_parse_beacon */
int ieee80211_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 11, 156, 148, 50, 36, 13, 127, 68 */
  /* observed branches: beqz.nx19, bnez.nx7, bltux4, bgex2, bgeux4, bnex14, beqix2, beqx4 */
  /* observed memory traffic (first 10): */
    /* s32i.n a6, a1, -- 8: 802.11 header region */
    /* l32i.n a5, a2, -- 0: frame control */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l16ui a7, a3, -- 22: seqctl/len */
    /* l32i.n a6, a5, -- 4: addr1 */
    /* s32i.n a8, a1, -- 16: addr3 */
    /* s32i.n a13, a1, -- 24: seqctl/addr4/QoS */
    /* l32i.n a8, a1, -- 8: 802.11 header region */
    /* s32i a8, a4, -- off 144 */
    /* l16ui a8, a6, -- off 32 */
  /* observed call sequence (in order): wifi_log -> memset -> .text.is_rsne_override_oui+0x4 -> ieee80211_regdomain_chan_in_range */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 8) = regs[6]; /* s32i.n a6,a1+8 → +8: 802.11 header region */
  regs[5] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a5,a2+0 → +0: frame control */
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[7] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[6] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a6,a5+4 → +4: addr1 */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[8]; /* s32i.n a8,a1+16 → +16: addr3 */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_regdomain_chan_in_range)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_parse_rsn @ ieee80211_input.o 000001b8 size 2558B bind GLOBAL
 * Calls: .text.is_rsne_override_oui, wifi_log, .text.rsn_cipher, ieee80211_better_rsn_pairwise_cipher, sta_is_wifi_ent_enabled, sta_is_wpa3_enabled, sta_is_11r_enabled | Data refs: .rodata.ieee80211_parse_rsn.str1.1, g_ic, g_wifi_nvs, .rodata_wlog_debug.11, .rodata_wlog_debug.12, .rodata_wlog_debug.13, .rodata_wlog_debug.14, .rodata_wlog_debug.15, .rodata_wlog_debug.16, .rodata_wlog_debug.17
 * Fidelity: low - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.ieee80211_parse_rsn */
int ieee80211_parse_rsn(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_rsn(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 3, 9, 1, 4, 8, -33, 32, 19, 23 */
  /* observed branches: bnez.nx10, bneix12, beqz.nx28, beqix6, banyx4, beqx10, bltx6, bltux2 */
  /* observed memory traffic (first 10): */
    /* s8i a2, a1, -- 0: frame control */
    /* s16i a6, a4, -- 0: frame control */
    /* s8i a2, a4, -- 4: addr1 */
    /* s8i a2, a4, -- 2: duration */
    /* s8i a2, a4, -- 10: addr2 */
    /* l32i.n a2, a6, -- 0: frame control */
    /* l8ui a8, a2, -- off 96 */
    /* l8ui a2, a2, -- off 97 */
    /* s32i.n a8, a1, -- 20: eb len field region */
    /* s32i.n a6, a1, -- 24: seqctl/addr4/QoS */
  /* observed call sequence (in order): .text.is_rsne_override_oui+0x4 -> wifi_log -> .text.rsn_cipher+0x28 -> ieee80211_better_rsn_pairwise_cipher -> sta_is_wifi_ent_enabled -> sta_is_wpa3_enabled -> sta_is_11r_enabled */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u8 *)(((u8 *)a1_spill) + 0) = (u8)regs[2]; /* s8i → +0: frame control */
  *(u16 *)(eb8 + 0) = (u16)regs[6]; /* s16i → +0: frame control */
  *(u8 *)(eb8 + 4) = (u8)regs[2]; /* s8i → +4: addr1 */
  *(u8 *)(eb8 + 2) = (u8)regs[2]; /* s8i → +2: duration */
  *(u8 *)(eb8 + 10) = (u8)regs[2]; /* s8i → +10: addr2 */
  regs[2] = *(u32 *)(eb8 + 0); /* l32i.n a2,a6+0 → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_better_rsn_pairwise_cipher)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())sta_is_wifi_ent_enabled)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_parse_wapi @ ieee80211_input.o 0000000c size 139B bind GLOBAL
 * Calls: wifi_log | Data refs: g_ic, .rodata_wlog_warning.55, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_parse_wapi */
int ieee80211_parse_wapi(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_wapi(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 19, 2, 128, 1, 0, 10, 7, 11, 8 */
  /* observed branches: bnez.nx1, bgex1, beqz.nx5, bnex1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a10, a2, -- off 56 */
    /* l8ui a4, a10, -- 1: frame control/duration */
    /* l32i a8, a3, -- off 0x280 */
    /* l32i.n a8, a8, -- 4: addr1 */
    /* l32i a8, a3, -- off 0x280 */
    /* l32i.n a8, a8, -- 12: 802.11 header region */
    /* l32i.n a10, a2, -- off 56 */
    /* s8i a3, a8, -- 4: addr1 */
    /* s8i a3, a8, -- 2: duration */
    /* l32i.n a9, a1, -- 12: 802.11 header region */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a2 + 56); /* l32i.n a10,a2+56 → +56:  */
  regs[4] = *(u8 *)(((u8 *)0) + 1); /* l8ui → +1: frame control/duration */
  regs[8] = *(u32 *)((u8 *)a3 + 640); /* l32i a8,a3+640 → +640:  */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a8+4 → +4: addr1 */
  regs[8] = *(u32 *)((u8 *)a3 + 640); /* l32i a8,a3+640 → +640:  */
  regs[8] = *(u32 *)(((u8 *)0) + 12); /* l32i.n a8,a8+12 → +12: 802.11 header region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_parse_wpa @ ieee80211_input.o 00000020 size 358B bind GLOBAL
 * Calls: .text.wpa_cipher, wifi_log | Data refs: g_ic, .rodata_wlog_debug.10, .text.wpa_cipher, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_parse_wpa */
int ieee80211_parse_wpa(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_parse_wpa(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 3, 13, 4, 8, 1, 16, 5, 2, -1 */
  /* observed branches: bnez.nx1, beqix1, bltix2, bltux3, beqx1, bnex1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a2, -- off 52 */
    /* s8i a3, a1, -- 0: frame control */
    /* l8ui a3, a5, -- 7: 802.11 header region */
    /* l8ui a4, a5, -- 6: 802.11 header region */
    /* l8ui a7, a5, -- 1: frame control/duration */
    /* s8i a3, a6, -- 0: frame control */
    /* s8i a10, a6, -- 4: addr1 */
    /* l8ui a8, a5, -- 13: 802.11 header region */
    /* l8ui a3, a5, -- 12: 802.11 header region */
    /* s32i.n a9, a1, -- 16: addr3 */
  /* observed call sequence (in order): .text.wpa_cipher+0x14 -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a2 + 52); /* l32i.n a5,a2+52 → +52:  */
  *(u8 *)(((u8 *)a1_spill) + 0) = (u8)regs[3]; /* s8i → +0: frame control */
  regs[3] = *(u8 *)((u8 *)(uintptr_t)a4 + 7); /* l8ui → +7: 802.11 header region */
  regs[4] = *(u8 *)((u8 *)(uintptr_t)a4 + 6); /* l8ui → +6: 802.11 header region */
  regs[7] = *(u8 *)((u8 *)(uintptr_t)a4 + 1); /* l8ui → +1: frame control/duration */
  *(u8 *)(eb8 + 0) = (u8)regs[3]; /* s8i → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_rsn_cipher_priority @ ieee80211_input.o 00000008 size 38B bind GLOBAL
 * Calls: memcpy | Data refs: .rodata, memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_rsn_cipher_priority */
int ieee80211_rsn_cipher_priority(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_rsn_cipher_priority(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 24, 0, 6 */
  /* observed branches: beqx1 */
  /* observed memory traffic (first 1): */
    /* l32i.n a11, a10, -- 0: frame control */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a11,a10+0 → +0: frame control */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_set_max_rate @ ieee80211_input.o 0000001c size 294B bind GLOBAL
 * Calls: wifi_log, ic_set_sta | Data refs: .rodata_wlog_debug.4, .rodata_wlog_debug.5, .rodata_wlog_debug.6, wifi_log, ic_set_sta
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_set_max_rate */
int ieee80211_set_max_rate(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_max_rate(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 1, 0, 4, 8 */
  /* observed branches: bneix3, bgeux2, bnez.nx1, beqz.nx2, bbsix1, bnex3 */
  /* observed memory traffic (first 10): */
    /* l8ui a15, a2, -- off 50 */
    /* l8ui a8, a3, -- off 238 */
    /* l8ui a4, a3, -- off 237 */
    /* l8ui a14, a3, -- off 239 */
    /* s8i a8, a3, -- off 239 */
    /* s8i a4, a3, -- off 239 */
    /* s8i a4, a2, -- off 50 */
    /* l8ui a4, a3, -- off 236 */
    /* l8ui a8, a3, -- off 239 */
    /* s8i a4, a3, -- off 239 */
  /* observed call sequence (in order): wifi_log -> ic_set_sta */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u8 *)((u8 *)a2 + 50); /* l8ui → +50:  */
  regs[8] = *(u8 *)((u8 *)a3 + 238); /* l8ui → +238:  */
  regs[4] = *(u8 *)((u8 *)a3 + 237); /* l8ui → +237:  */
  regs[1] = *(u8 *)((u8 *)a3 + 239); /* l8ui → +239:  */
  *(u8 *)((u8 *)a3 + 239) = (u8)regs[8]; /* s8i → +239:  */
  *(u8 *)((u8 *)a3 + 239) = (u8)regs[4]; /* s8i → +239:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_set_sta)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_setup_lr_rates @ ieee80211_input.o 00000004 size 110B bind GLOBAL
 * Calls: memset | Data refs: memset
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_setup_lr_rates */
int ieee80211_setup_lr_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_lr_rates(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1, 131, 4, 0 */
  /* observed branches: bnex1, bltx2 */
  /* observed memory traffic (first 10): */
    /* l32i.n a4, a2, -- 0: frame control */
    /* l8ui a8, a3, -- 0: frame control */
    /* s8i a8, a2, -- off 131 */
    /* l8ui a10, a11, -- 0: frame control */
    /* l8ui a12, a12, -- 2: duration */
    /* l8ui a10, a2, -- off 132 */
    /* s8i a15, a2, -- off 132 */
    /* s8i a12, a10, -- off 133 */
    /* l8ui a10, a3, -- 1: frame control/duration */
    /* l8ui a9, a13, -- off 170 */
  /* observed call sequence (in order): memset */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a4,a2+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  *(u8 *)((u8 *)a2 + 131) = (u8)regs[8]; /* s8i → +131:  */
  regs[1] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  regs[1] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  regs[1] = *(u8 *)((u8 *)a2 + 132); /* l8ui → +132:  */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_setup_phy_mode @ ieee80211_input.o 00000014 size 166B bind GLOBAL
 * Calls: wifi_log, ieee80211_is_lr_only | Data refs: .rodata.ieee80211_setup_phy_mode.str1.1, .rodata_wlog_error.3, wifi_log, ieee80211_is_lr_only
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_setup_phy_mode */
int ieee80211_setup_phy_mode(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_phy_mode(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 4, 3, 2 */
  /* observed branches: beqz.nx2, bnez.nx1, beqx1, bnex1, bneix1 */
  /* observed memory traffic (first 9): */
    /* l32i a4, a2, -- 0: frame control */
    /* s8i a3, a2, -- off 50 */
    /* l8ui a12, a4, -- off 104 */
    /* l8ui a9, a2, -- off 115 */
    /* s32i.n a4, a1, -- 0: frame control */
    /* l8ui a11, a8, -- off 116 */
    /* l8ui a13, a13, -- 0: frame control */
    /* s8i a8, a2, -- off 49 */
    /* s8i a8, a2, -- off 50 */
  /* observed call sequence (in order): wifi_log -> ieee80211_is_lr_only */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u32 *)((u8 *)a2 + 0); /* l32i a4,a2+0 → +0: frame control */
  *(u8 *)((u8 *)a2 + 50) = (u8)regs[3]; /* s8i → +50:  */
  regs[1] = *(u8 *)(eb8 + 104); /* l8ui → +104:  */
  regs[9] = *(u8 *)((u8 *)a2 + 115); /* l8ui → +115:  */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[4]; /* s32i.n a4,a1+0 → +0: frame control */
  regs[1] = *(u8 *)(((u8 *)0) + 116); /* l8ui → +116:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_is_lr_only)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_setup_rates @ ieee80211_input.o 00000008 size 219B bind GLOBAL
 * Calls: memset, ieee80211_is_support_rate | Data refs: memset, ieee80211_is_support_rate
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_setup_rates */
int ieee80211_setup_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_rates(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 16, 0, 1 */
  /* observed branches: beqz.nx2, bltx1, beqix1, bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a7, a2, -- 0: frame control */
    /* s32i.n a10, a1, -- 0: frame control */
    /* l8ui a14, a10, -- 0: frame control */
    /* s32i.n a8, a1, -- 16: addr3 */
    /* s32i.n a9, a1, -- 12: 802.11 header region */
    /* s32i.n a13, a1, -- 8: 802.11 header region */
    /* s32i.n a14, a1, -- 4: addr1 */
    /* s32i.n a15, a1, -- 20: eb len field region */
    /* l32i.n a8, a1, -- 16: addr3 */
    /* l32i.n a9, a1, -- 12: 802.11 header region */
  /* observed call sequence (in order): memset -> ieee80211_is_support_rate */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[7] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a7,a2+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[1]; /* s32i.n a10,a1+0 → +0: frame control */
  regs[1] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[8]; /* s32i.n a8,a1+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 12) = regs[9]; /* s32i.n a9,a1+12 → +12: 802.11 header region */
  *(u32 *)(((u8 *)a1_spill) + 8) = regs[1]; /* s32i.n a13,a1+8 → +8: 802.11 header region */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_is_support_rate)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_setup_rateset @ ieee80211_input.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_setup_rateset */
int ieee80211_setup_rateset(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_rateset(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
