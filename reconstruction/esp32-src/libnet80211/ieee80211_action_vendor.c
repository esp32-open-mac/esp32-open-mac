/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_action_vendor.o
 * Blob: esp32/libnet80211.a(ieee80211_action_vendor.o) -> /tmp/re_esp32/libnet80211/ieee80211_action_vendor.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_action_vendor.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): chm_get_current_band, cnx_node_search, g_espnow_user_oui, g_ic, g_osi_funcs_p, g_wifi_global_lock, g_wifi_menuconfig, hal_now, ic_get_default_sched, ic_get_espnow_rate, ic_get_random, ieee80211_add_ie_vendor_esp_now, ieee80211_alloc_tx_buf, ieee80211_espnow_get_init_flag, ieee80211_ethbroadcast, ieee80211_post_hmac_tx, ieee80211_recv_action_register, memcmp, memcpy, roundup2, wifi_get_macaddr
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
int get_iav_key(void *a2, void *a3, unsigned a4, unsigned a5);
int get_iav_key(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_action_vendor_reset_seq_state(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_action_vendor_reset_seq_state(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_action_vendor_spec_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_action_vendor_spec_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_action_vendor_spec_esp(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_action_vendor_spec_esp(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_construct_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_construct_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_vendor_esp_now(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_vendor_esp_now(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int register_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int register_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int register_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int register_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int unregister_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int unregister_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int unregister_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int unregister_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int chm_get_current_band();
extern int cnx_node_search();
extern int hal_now();
extern int ic_get_default_sched();
extern int ic_get_espnow_rate();
extern int ic_get_random();
extern int ieee80211_add_ie_vendor_esp_now();
extern int ieee80211_alloc_tx_buf();
extern int ieee80211_espnow_get_init_flag();
extern int ieee80211_post_hmac_tx();
extern int ieee80211_recv_action_register();
extern int roundup2();
extern int wifi_get_macaddr();

/* get_iav_key @ ieee80211_action_vendor.o 00000004 size 26B bind GLOBAL
 * Calls: none | Data refs: .bss.get_key_cb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.get_iav_key */
int get_iav_key(void *a2, void *a3, unsigned a4, unsigned a5);
int get_iav_key(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx2 */
  /* observed memory traffic (first 1): */
    /* l32i.n a8, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_action_vendor_reset_seq_state @ ieee80211_action_vendor.o 00000008 size 30B bind GLOBAL
 * Calls: none | Data refs: .bss.s_random_seq_num_set, .data.s_global_vendor_seq
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_action_vendor_reset_seq_state */
int ieee80211_action_vendor_reset_seq_state(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_action_vendor_reset_seq_state(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed memory traffic (first 2): */
    /* s8i a9, a8, -- 0: frame control */
    /* s16i a9, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[9]; /* s8i → +0: frame control */
  *(u16 *)(((u8 *)0) + 0) = (u16)regs[9]; /* s16i → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_action_vendor_spec_attach @ ieee80211_action_vendor.o 0000000c size 44B bind GLOBAL
 * Calls: ieee80211_recv_action_register | Data refs: ieee80211_recv_action_vendor_spec, g_ic, ieee80211_recv_action_register
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_action_vendor_spec_attach */
int ieee80211_action_vendor_spec_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_action_vendor_spec_attach(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 127 */
  /* observed memory traffic (first 3): */
    /* s32i a9, a8, -- off 200 */
    /* s32i a9, a8, -- off 204 */
    /* s8i a9, a8, -- off 212 */
  /* observed call sequence (in order): ieee80211_recv_action_register */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 200) = regs[9]; /* s32i a9,a8+200 → +200:  */
  *(u32 *)(((u8 *)0) + 204) = regs[9]; /* s32i a9,a8+204 → +204:  */
  *(u8 *)(((u8 *)0) + 212) = (u8)regs[9]; /* s8i → +212:  */
  (void)((int(*)())ieee80211_recv_action_register)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_action_vendor_spec_esp @ ieee80211_action_vendor.o 0000000c size 89B bind GLOBAL
 * Calls: ic_get_random | Data refs: .rodata.ieee80211_add_action_vendor_spec_esp.str1.1, .bss.avs_tx_content, ic_get_random
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_action_vendor_spec_esp */
int ieee80211_add_action_vendor_spec_esp(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_action_vendor_spec_esp(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 127 */
  /* observed branches: beqx1 */
  /* observed memory traffic (first 10): */
    /* l8ui a10, a8, -- 0: frame control */
    /* l8ui a9, a8, -- 1: frame control/duration */
    /* l8ui a8, a8, -- 2: duration */
    /* s8i a3, a2, -- 0: frame control */
    /* s8i a10, a2, -- 1: frame control/duration */
    /* s8i a9, a2, -- 2: duration */
    /* s8i a8, a2, -- 3: 802.11 header region */
    /* l32i.n a8, a3, -- 0: frame control */
    /* s8i a10, a2, -- 4: addr1 */
    /* s8i a12, a2, -- 5: 802.11 header region */
  /* observed call sequence (in order): ic_get_random */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  regs[9] = *(u8 *)(((u8 *)0) + 1); /* l8ui → +1: frame control/duration */
  regs[8] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[3]; /* s8i → +0: frame control */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[1]; /* s8i → +1: frame control/duration */
  *(u8 *)((u8 *)a2 + 2) = (u8)regs[9]; /* s8i → +2: duration */
  (void)((int(*)())ic_get_random)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_alloc_action_vendor_spec @ ieee80211_action_vendor.o 00000014 size 261B bind GLOBAL
 * Calls: roundup2, ieee80211_alloc_tx_buf, ieee80211_add_action_vendor_spec_esp, ieee80211_add_ie_vendor_esp_now | Data refs: roundup2, ieee80211_alloc_tx_buf, ieee80211_add_action_vendor_spec_esp, ieee80211_add_ie_vendor_esp_now
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_alloc_action_vendor_spec */
int ieee80211_alloc_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 250, 1, 249, 8, 4, 0, 32, 24 */
  /* observed branches: bgeux1, beqz.nx2, bltux1 */
  /* observed memory traffic (first 10): */
    /* l32i a3, a6, -- off 160 */
    /* l32i.n a2, a3, -- 4: addr1 */
    /* l32i.n a8, a10, -- 4: addr1 */
    /* l32i.n a8, a8, -- 4: addr1 */
    /* s16i a3, a2, -- 22: seqctl/len */
    /* l32i a3, a6, -- off 160 */
    /* l32i a11, a6, -- 152: key PN/counter region */
    /* l32i a12, a6, -- 156: key PN/counter region */
    /* s32i a9, a6, -- 152: key PN/counter region */
    /* s32i a3, a6, -- 156: key PN/counter region */
  /* observed call sequence (in order): roundup2 -> ieee80211_alloc_tx_buf -> ieee80211_add_action_vendor_spec_esp -> ieee80211_add_ie_vendor_esp_now */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)(eb8 + 160); /* l32i a3,a6+160 → +160:  */
  regs[2] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a2,a3+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a10+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a8+4 → +4: addr1 */
  *(u16 *)((u8 *)a2 + 22) = (u16)regs[3]; /* s16i → +22: seqctl/len */
  regs[3] = *(u32 *)(eb8 + 160); /* l32i a3,a6+160 → +160:  */
  (void)((int(*)())roundup2)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_alloc_tx_buf)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_action_vendor_spec_esp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_ie_vendor_esp_now)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_construct_action_vendor_spec @ ieee80211_action_vendor.o 00000074 size 877B bind GLOBAL
 * Calls: chm_get_current_band, wifi_get_macaddr, get_iav_key, memcmp, cnx_node_search, ieee80211_alloc_action_vendor_spec, memcpy, hal_now, ic_get_default_sched, ic_get_espnow_rate, ieee80211_espnow_get_init_flag | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic, ieee80211_ethbroadcast, g_wifi_menuconfig, .bss.s_random_seq_num_set, .data.s_global_vendor_seq, g_ic+0x200, chm_get_current_band, wifi_get_macaddr
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_construct_action_vendor_spec */
int ieee80211_construct_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_construct_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 6, 0, -1, 1, 208, 64, 7, 128 */
  /* observed branches: bnez.nx8, beqz.nx9, bneix6, bbcix2, bnex1 */
  /* observed memory traffic (first 10): */
    /* s32i.n a7, a1, -- 16: addr3 */
    /* s32i a5, a1, -- 24: seqctl/addr4/QoS */
    /* s32i a6, a1, -- 28: HT */
    /* s32i.n a10, a1, -- 20: eb len field region */
    /* l32i.n a6, a8, -- 0: frame control */
    /* l32i a6, a6, -- off 84 */
    /* l32i.n a10, a5, -- 0: frame control */
    /* s32i.n a8, a1, -- off 32 */
    /* l32i.n a8, a1, -- off 32 */
    /* l32i.n a6, a6, -- 16: addr3 */
  /* observed call sequence (in order): chm_get_current_band -> wifi_get_macaddr -> get_iav_key -> memcmp -> cnx_node_search -> ieee80211_alloc_action_vendor_spec -> memcpy -> hal_now -> ic_get_default_sched -> ic_get_espnow_rate -> ieee80211_espnow_get_init_flag */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[7]; /* s32i.n a7,a1+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 24) = regs[5]; /* s32i a5,a1+24 → +24: seqctl/addr4/QoS */
  *(u32 *)(((u8 *)a1_spill) + 28) = regs[6]; /* s32i a6,a1+28 → +28: HT */
  *(u32 *)(((u8 *)a1_spill) + 20) = regs[1]; /* s32i.n a10,a1+20 → +20: eb len field region */
  regs[6] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a6,a8+0 → +0: frame control */
  regs[6] = *(u32 *)(eb8 + 84); /* l32i a6,a6+84 → +84:  */
  (void)((int(*)())chm_get_current_band)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())get_iav_key)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_alloc_action_vendor_spec)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_default_sched)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_espnow_rate)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_espnow_get_init_flag)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_recv_action_vendor_esp_now @ ieee80211_action_vendor.o 00000028 size 315B bind GLOBAL
 * Calls: memcmp, memcpy | Data refs: .rodata.ieee80211_add_action_vendor_spec_esp.str1.1, .bss.avs_rx_content, g_espnow_user_oui, g_osi_funcs_p, .bss.avs_cb, memcmp, memcpy
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_recv_action_vendor_esp_now */
int ieee80211_recv_action_vendor_esp_now(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_vendor_esp_now(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 14, 3, 4, 0, 221 */
  /* observed branches: bltux1, bbcix1, bnez.nx1, bnex1, bgex1, bneix1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l8ui a7, a3, -- 1: frame control/duration */
    /* l8ui a7, a4, -- 4: addr1 */
    /* l8ui a8, a6, -- 1: frame control/duration */
    /* s8i a7, a2, -- 0: frame control */
    /* l8ui a7, a6, -- 2: duration */
    /* s8i a8, a2, -- 1: frame control/duration */
    /* l8ui a6, a6, -- 3: 802.11 header region */
    /* s8i a7, a2, -- 2: duration */
    /* s8i a6, a2, -- 3: 802.11 header region */
    /* l8ui a2, a8, -- 0: frame control */
  /* observed call sequence (in order): memcmp -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[7] = *(u8 *)((u8 *)a3 + 1); /* l8ui → +1: frame control/duration */
  regs[7] = *(u8 *)(eb8 + 4); /* l8ui → +4: addr1 */
  regs[8] = *(u8 *)(eb8 + 1); /* l8ui → +1: frame control/duration */
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[7]; /* s8i → +0: frame control */
  regs[7] = *(u8 *)(eb8 + 2); /* l8ui → +2: duration */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[8]; /* s8i → +1: frame control/duration */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_recv_action_vendor_spec @ ieee80211_action_vendor.o 00000014 size 134B bind GLOBAL
 * Calls: memcpy, get_iav_key, ieee80211_recv_action_vendor_esp_now | Data refs: .bss.avs_cb, memcpy, get_iav_key, ieee80211_recv_action_vendor_esp_now
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_recv_action_vendor_spec */
int ieee80211_recv_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 6 */
  /* observed branches: bnez.nx1, bbcix2, beqz.nx2, bneix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l8ui a8, a3, -- 1: frame control/duration */
    /* l32i a8, a10, -- off 160 */
    /* l8ui a9, a3, -- 27: 802.11 header region */
    /* l8ui a8, a3, -- 25: 802.11 header region */
    /* l8ui a9, a3, -- 28: HT */
    /* l8ui a9, a3, -- 24: seqctl/addr4/QoS */
    /* l8ui a9, a3, -- 29: 802.11 header region */
    /* l8ui a9, a3, -- off 31 */
    /* l8ui a11, a3, -- 30: 802.11 header region */
  /* observed call sequence (in order): memcpy -> get_iav_key -> ieee80211_recv_action_vendor_esp_now */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)a3 + 1); /* l8ui → +1: frame control/duration */
  regs[8] = *(u32 *)(((u8 *)0) + 160); /* l32i a8,a10+160 → +160:  */
  regs[9] = *(u8 *)((u8 *)a3 + 27); /* l8ui → +27: 802.11 header region */
  regs[8] = *(u8 *)((u8 *)a3 + 25); /* l8ui → +25: 802.11 header region */
  regs[9] = *(u8 *)((u8 *)a3 + 28); /* l8ui → +28: HT */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())get_iav_key)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_recv_action_vendor_esp_now)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_action_vendor_spec @ ieee80211_action_vendor.o 00000008 size 50B bind GLOBAL
 * Calls: ieee80211_construct_action_vendor_spec, ieee80211_post_hmac_tx | Data refs: ieee80211_construct_action_vendor_spec, ieee80211_post_hmac_tx
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_send_action_vendor_spec */
int ieee80211_send_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_vendor_spec(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed branches: bnez.nx1 */
  /* observed memory traffic (first 3): */
    /* s32i.n a8, a1, -- 16: addr3 */
    /* s32i.n a8, a1, -- 0: frame control */
    /* l32i.n a10, a1, -- 16: addr3 */
  /* observed call sequence (in order): ieee80211_construct_action_vendor_spec -> ieee80211_post_hmac_tx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[8]; /* s32i.n a8,a1+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[8]; /* s32i.n a8,a1+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)a1_spill) + 16); /* l32i.n a10,a1+16 → +16: addr3 */
  (void)((int(*)())ieee80211_construct_action_vendor_spec)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_post_hmac_tx)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* register_ieee80211_action_vendor_get_key_cb @ ieee80211_action_vendor.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: .bss.get_key_cb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.register_ieee80211_action_vendor_get_key_cb */
int register_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int register_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1, 0 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 1): */
    /* s32i.n a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* register_ieee80211_action_vendor_spec_cb @ ieee80211_action_vendor.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: .bss.avs_cb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.register_ieee80211_action_vendor_spec_cb */
int register_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int register_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1, 0 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 1): */
    /* s32i.n a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* unregister_ieee80211_action_vendor_get_key_cb @ ieee80211_action_vendor.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.get_key_cb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.unregister_ieee80211_action_vendor_get_key_cb */
int unregister_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int unregister_ieee80211_action_vendor_get_key_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 1): */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[9]; /* s32i.n a9,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* unregister_ieee80211_action_vendor_spec_cb @ ieee80211_action_vendor.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.avs_cb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.unregister_ieee80211_action_vendor_spec_cb */
int unregister_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int unregister_ieee80211_action_vendor_spec_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 1): */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[9]; /* s32i.n a9,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
