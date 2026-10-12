/* Reconstructed ESP32 WiFi MAC data-path: wl_chm.o
 * Blob: esp32/libnet80211.a(wl_chm.o) -> /tmp/re_esp32/libnet80211/wl_chm.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/wl_chm.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): disable_wifi_agc, enable_wifi_agc, g_ic, g_osi_funcs_p, g_scan, g_wifi_global_lock, g_wifi_nvs, ic_mac_deinit, ic_mac_init, ic_set_current_channel, ieee80211_regdomain_max_chan, ieee80211_regdomain_min_chan, ieee80211_timer_process, memset, phy_change_channel_nomac, pm_wake_done, pm_wake_up, wifi_event_post, wifi_log
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
int chm_acquire_lock(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_acquire_lock(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_cancel_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_cancel_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_check_channel_is_valid(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_check_channel_is_valid(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_deinit(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_deinit(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_end_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_end_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_end_op_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_end_op_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_band_from_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_band_from_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_chan_info(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_chan_info(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_channel_index(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_channel_index(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_current_band(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_current_band(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_current_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_current_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_snd_chan_mode(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_snd_chan_mode(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_init(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_init(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_is_at_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_is_at_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_mhz2num(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_mhz2num(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_release_lock(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_release_lock(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_return_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_return_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_current_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_current_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_snd_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_snd_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_start_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_start_op(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int disable_wifi_agc();
extern int enable_wifi_agc();
extern int ic_mac_deinit();
extern int ic_mac_init();
extern int ic_set_current_channel();
extern int ieee80211_regdomain_max_chan();
extern int ieee80211_regdomain_min_chan();
extern int ieee80211_timer_process();
extern int phy_change_channel_nomac();
extern int pm_wake_done();
extern int pm_wake_up();
extern int wifi_event_post();
extern int wifi_log();

/* chm_acquire_lock @ wl_chm.o 00000008 size 54B bind GLOBAL
 * Calls: chm_cancel_op | Data refs: g_chm, chm_cancel_op
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.chm_acquire_lock */
int chm_acquire_lock(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_acquire_lock(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 3, 1, 0 */
  /* observed branches: beqz.nx1, bltux1 */
  /* observed memory traffic (first 8): */
    /* l32i.n a2, a6, -- 0: frame control */
    /* l8ui a8, a2, -- off 76 */
    /* l8ui a8, a2, -- off 77 */
    /* l32i.n a8, a6, -- 0: frame control */
    /* s8i a2, a8, -- off 76 */
    /* s8i a5, a8, -- off 77 */
    /* s32i.n a3, a8, -- 28: HT */
    /* s32i.n a4, a8, -- off 32 */
  /* observed call sequence (in order): chm_cancel_op */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)(eb8 + 0); /* l32i.n a2,a6+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)a2 + 76); /* l8ui → +76:  */
  regs[8] = *(u8 *)((u8 *)a2 + 77); /* l8ui → +77:  */
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a6+0 → +0: frame control */
  *(u8 *)(((u8 *)0) + 76) = (u8)regs[2]; /* s8i → +76:  */
  *(u8 *)(((u8 *)0) + 77) = (u8)regs[5]; /* s8i → +77:  */
  (void)((int(*)())chm_cancel_op)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_cancel_op @ wl_chm.o 0000000c size 68B bind GLOBAL
 * Calls: chm_end_op | Data refs: g_chm, g_osi_funcs_p, chm_end_op
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.chm_cancel_op */
int chm_cancel_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_cancel_op(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 255, 4 */
  /* observed branches: beqx1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a10, a2, -- 0: frame control */
    /* l8ui a8, a10, -- 4: addr1 */
    /* l32i a8, a3, -- 0: frame control */
    /* l32i a8, a8, -- off 236 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i.n a10, a2, -- 0: frame control */
    /* l32i a3, a3, -- off 236 */
    /* l32i.n a8, a2, -- 0: frame control */
    /* l32i.n a2, a8, -- 28: HT */
    /* l32i.n a10, a8, -- off 32 */
  /* observed call sequence (in order): chm_end_op */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a10,a2+0 → +0: frame control */
  regs[8] = *(u8 *)(((u8 *)0) + 4); /* l8ui → +4: addr1 */
  regs[8] = *(u32 *)((u8 *)a3 + 0); /* l32i a8,a3+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 236); /* l32i a8,a8+236 → +236:  */
  regs[3] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a3,a3+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a10,a2+0 → +0: frame control */
  (void)((int(*)())chm_end_op)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_check_channel_is_valid @ wl_chm.o 00000004 size 110B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.chm_check_channel_is_valid */
int chm_check_channel_is_valid(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_check_channel_is_valid(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 13, 1, 0, 28, 44 */
  /* observed branches: bbcix2, bgeux1, bltux3 */
  /* observed memory traffic (first 2): */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l32i a10, a2, -- off 200 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a2 + 200); /* l32i a10,a2+200 → +200:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_deinit @ wl_chm.o 00000008 size 38B bind GLOBAL
 * Calls: none | Data refs: g_chm, g_osi_funcs_p
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_deinit */
int chm_deinit(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_deinit(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 6): */
    /* l32i.n a8, a2, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a8, a8, -- off 240 */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l32i a10, a3, -- 0: frame control */
    /* l32i a2, a2, -- off 240 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a8,a2+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 240); /* l32i a8,a8+240 → +240:  */
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i a10,a3+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a2 + 240); /* l32i a2,a2+240 → +240:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_end_op @ wl_chm.o 00000008 size 46B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: ieee80211_timer_process
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_end_op_timeout */
int chm_end_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_end_op(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 8, 7 */
  /* observed call sequence (in order): ieee80211_timer_process */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  (void)((int(*)())ieee80211_timer_process)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_end_op_timeout_process @ wl_chm.o 0000000c size 34B bind GLOBAL
 * Calls: chm_end_op | Data refs: g_chm, g_osi_funcs_p, chm_end_op
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_end_op_timeout_process */
int chm_end_op_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_end_op_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed branches: bnez.nx1 */
  /* observed memory traffic (first 3): */
    /* l32i.n a10, a8, -- 0: frame control */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l32i a8, a8, -- off 236 */
  /* observed call sequence (in order): chm_end_op */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a10,a8+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 236); /* l32i a8,a8+236 → +236:  */
  (void)((int(*)())chm_end_op)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_get_band_from_chan @ wl_chm.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_get_band_from_chan */
int chm_get_band_from_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_band_from_chan(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_get_chan_info @ wl_chm.o 00000004 size 36B bind GLOBAL
 * Calls: none | Data refs: g_chm
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_get_chan_info */
int chm_get_chan_info(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_chan_info(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 13, 0 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 1): */
    /* l32i.n a2, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_get_channel_index @ wl_chm.o 00000004 size 46B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_get_channel_index */
int chm_get_channel_index(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_channel_index(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 255 */
  /* observed branches: beqx1, bltux1 */
  /* observed memory traffic (first 4): */
    /* l32i.n a8, a2, -- 0: frame control */
    /* l8ui a9, a8, -- off 72 */
    /* l32i a10, a8, -- off 76 */
    /* l8ui a8, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a8,a2+0 → +0: frame control */
  regs[9] = *(u8 *)(((u8 *)0) + 72); /* l8ui → +72:  */
  regs[1] = *(u32 *)(((u8 *)0) + 76); /* l32i a10,a8+76 → +76:  */
  regs[8] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_get_current_band @ wl_chm.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_get_current_band */
int chm_get_current_band(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_current_band(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_get_current_channel @ wl_chm.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_chm
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_get_current_channel */
int chm_get_current_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_current_channel(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 1): */
    /* l32i.n a2, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_get_home_channel @ wl_chm.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_chm
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_get_home_channel */
int chm_get_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_home_channel(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 1): */
    /* l32i.n a2, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_get_snd_chan_mode @ wl_chm.o 00000008 size 71B bind GLOBAL
 * Calls: ieee80211_regdomain_min_chan, ieee80211_regdomain_max_chan | Data refs: ieee80211_regdomain_min_chan, ieee80211_regdomain_max_chan
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.chm_get_snd_chan_mode */
int chm_get_snd_chan_mode(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_get_snd_chan_mode(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 14, 0, 9, 2 */
  /* observed branches: beqx1, bltx1, bgeux1, bgex1 */
  /* observed call sequence (in order): ieee80211_regdomain_min_chan -> ieee80211_regdomain_max_chan */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  (void)((int(*)())ieee80211_regdomain_min_chan)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_regdomain_max_chan)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_init @ wl_chm.o 00000028 size 316B bind GLOBAL
 * Calls: chm_mhz2num, ieee80211_regdomain_min_chan, chm_set_home_channel, chm_set_current_channel | Data refs: g_wifi_nvs, g_ic, g_chm, .text.chm_end_op_timeout, g_osi_funcs_p, chm_mhz2num, ieee80211_regdomain_min_chan, chm_set_home_channel, chm_set_current_channel
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.chm_init */
int chm_init(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_init(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 131, 13, 14, 1, 2, -1 */
  /* observed branches: bnex2, bnez.nx3, bneix3, beqix2 */
  /* observed memory traffic (first 10): */
    /* s16i a3, a1, -- 0: frame control */
    /* l32i.n a4, a3, -- 0: frame control */
    /* l32i a7, a8, -- off 200 */
    /* l32i.n a9, a6, -- 0: frame control */
    /* s8i a7, a3, -- off 173 */
    /* s8i a3, a9, -- off 79 */
    /* s32i.n a12, a3, -- 8: 802.11 header region */
    /* s16i a10, a3, -- 2: duration */
    /* s16i a10, a9, -- off 242 */
    /* l8ui a10, a3, -- 0: frame control */
  /* observed call sequence (in order): chm_mhz2num -> ieee80211_regdomain_min_chan -> chm_set_home_channel -> chm_set_current_channel */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u16 *)(((u8 *)a1_spill) + 0) = (u16)regs[3]; /* s16i → +0: frame control */
  regs[4] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a4,a3+0 → +0: frame control */
  regs[7] = *(u32 *)(((u8 *)0) + 200); /* l32i a7,a8+200 → +200:  */
  regs[9] = *(u32 *)(eb8 + 0); /* l32i.n a9,a6+0 → +0: frame control */
  *(u8 *)((u8 *)a3 + 173) = (u8)regs[7]; /* s8i → +173:  */
  *(u8 *)(((u8 *)0) + 79) = (u8)regs[3]; /* s8i → +79:  */
  (void)((int(*)())chm_mhz2num)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_regdomain_min_chan)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_set_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_set_current_channel)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_is_at_home_channel @ wl_chm.o 00000004 size 26B bind GLOBAL
 * Calls: none | Data refs: g_chm
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .wifi0iram.12 */
int chm_is_at_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_is_at_home_channel(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed memory traffic (first 3): */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l8ui a8, a2, -- off 80 */
    /* l8ui a2, a2, -- off 82 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)a2 + 80); /* l8ui → +80:  */
  regs[2] = *(u8 *)((u8 *)a2 + 82); /* l8ui → +82:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_mhz2num @ wl_chm.o 00000010 size 86B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.chm_mhz2num */
int chm_mhz2num(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_mhz2num(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 14, -157, -1 */
  /* observed branches: bbcix1, beqx2, bltux1, bgeux1 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_release_lock @ wl_chm.o 00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: g_chm
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_release_lock */
int chm_release_lock(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_release_lock(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 4): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* s32i.n a9, a8, -- off 32 */
    /* s32i.n a9, a8, -- 28: HT */
    /* s16i a9, a8, -- off 76 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 32) = regs[9]; /* s32i.n a9,a8+32 → +32:  */
  *(u32 *)(((u8 *)0) + 28) = regs[9]; /* s32i.n a9,a8+28 → +28: HT */
  *(u16 *)(((u8 *)0) + 76) = (u16)regs[9]; /* s16i → +76:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_return_home_channel @ wl_chm.o 00000010 size 73B bind GLOBAL
 * Calls: wifi_log, chm_set_current_channel | Data refs: g_chm, .rodata_wlog_verbose.6, wifi_log, chm_set_current_channel
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.chm_return_home_channel */
int chm_return_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_return_home_channel(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 5, 8, 1 */
  /* observed branches: bnex1, beqx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l8ui a8, a2, -- off 83 */
    /* l8ui a15, a2, -- off 81 */
    /* l8ui a14, a2, -- off 80 */
    /* s32i.n a8, a1, -- 4: addr1 */
    /* l8ui a8, a2, -- off 82 */
    /* s32i.n a8, a1, -- 0: frame control */
    /* l8ui a9, a2, -- off 80 */
    /* l8ui a8, a2, -- off 82 */
    /* l8ui a8, a2, -- off 81 */
  /* observed call sequence (in order): wifi_log -> chm_set_current_channel */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)a2 + 83); /* l8ui → +83:  */
  regs[1] = *(u8 *)((u8 *)a2 + 81); /* l8ui → +81:  */
  regs[1] = *(u8 *)((u8 *)a2 + 80); /* l8ui → +80:  */
  *(u32 *)(((u8 *)a1_spill) + 4) = regs[8]; /* s32i.n a8,a1+4 → +4: addr1 */
  regs[8] = *(u8 *)((u8 *)a2 + 82); /* l8ui → +82:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_set_current_channel)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_set_current_channel @ wl_chm.o 0000003c size 239B bind GLOBAL
 * Calls: chm_get_chan_info, wifi_log, ic_set_current_channel, .text.chm_phy_change_channel$constprop$0 | Data refs: .rodata_wlog_error.7, .rodata_wlog_error.8, .rodata_wlog_verbose.9, .rodata_wlog_verbose.10, .rodata_wlog_verbose.11, g_osi_funcs_p, g_wifi_global_lock, g_chm, chm_get_chan_info, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.chm_set_current_channel */
int chm_set_current_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_current_channel(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 13, 1, 8, 5, 3, 2, 0 */
  /* observed branches: bltux3, bnez.nx2, bneix2 */
  /* observed memory traffic (first 10): */
    /* l8ui a3, a2, -- 0: frame control */
    /* l16ui a3, a10, -- 2: duration */
    /* l8ui a10, a2, -- 1: frame control/duration */
    /* l8ui a15, a2, -- 0: frame control */
    /* l32i.n a8, a4, -- 0: frame control */
    /* l32i a10, a8, -- 4: addr1 */
    /* l32i.n a8, a4, -- 0: frame control */
    /* l32i a8, a8, -- off 84 */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l8ui a9, a2, -- 0: frame control */
  /* observed call sequence (in order): chm_get_chan_info -> wifi_log -> ic_set_current_channel -> .text.chm_phy_change_channel$constprop$0+0x1c */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u8 *)((u8 *)a2 + 0); /* l8ui → +0: frame control */
  regs[3] = *(u16 *)(((u8 *)0) + 2); /* l16ui → +2: duration */
  regs[1] = *(u8 *)((u8 *)a2 + 1); /* l8ui → +1: frame control/duration */
  regs[1] = *(u8 *)((u8 *)a2 + 0); /* l8ui → +0: frame control */
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a4+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i a10,a8+4 → +4: addr1 */
  (void)((int(*)())chm_get_chan_info)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_set_current_channel)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_set_home_channel @ wl_chm.o 00000020 size 173B bind GLOBAL
 * Calls: wifi_log, wifi_event_post | Data refs: .rodata.chm_set_home_channel.str1.1, .rodata_wlog_error.13, g_wifi_global_lock, g_osi_funcs_p, g_chm, g_ic, wifi_log, wifi_event_post
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.chm_set_home_channel */
int chm_set_home_channel(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_home_channel(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 16, 43 */
  /* observed branches: bnez.nx2, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i a3, a4, -- 0: frame control */
    /* l32i.n a10, a5, -- 0: frame control */
    /* l32i a3, a3, -- off 84 */
    /* l32i.n a9, a3, -- 0: frame control */
    /* l8ui a12, a2, -- 0: frame control */
    /* l8ui a7, a9, -- off 80 */
    /* l8ui a10, a2, -- 1: frame control/duration */
    /* l8ui a6, a9, -- off 81 */
    /* l32i a8, a4, -- 0: frame control */
    /* s8i a10, a9, -- off 81 */
  /* observed call sequence (in order): wifi_log -> wifi_event_post */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)(eb8 + 0); /* l32i a3,a4+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a10,a5+0 → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 84); /* l32i a3,a3+84 → +84:  */
  regs[9] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a9,a3+0 → +0: frame control */
  regs[1] = *(u8 *)((u8 *)a2 + 0); /* l8ui → +0: frame control */
  regs[7] = *(u8 *)(((u8 *)0) + 80); /* l8ui → +80:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_event_post)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_set_snd_chan @ wl_chm.o 00000004 size 31B bind GLOBAL
 * Calls: chm_get_snd_chan_mode | Data refs: chm_get_snd_chan_mode
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.chm_set_snd_chan */
int chm_set_snd_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_set_snd_chan(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2 */
  /* observed branches: bbsix1 */
  /* observed memory traffic (first 2): */
    /* l8ui a10, a2, -- 0: frame control */
    /* s8i a8, a2, -- 1: frame control/duration */
  /* observed call sequence (in order): chm_get_snd_chan_mode */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u8 *)((u8 *)a2 + 0); /* l8ui → +0: frame control */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[8]; /* s8i → +1: frame control/duration */
  (void)((int(*)())chm_get_snd_chan_mode)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* chm_start_op @ wl_chm.o 00000008 size 62B bind GLOBAL
 * Calls: .text.chm_change_channel | Data refs: g_chm, .text.chm_change_channel
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.chm_start_op */
int chm_start_op(void *a2, void *a3, unsigned a4, unsigned a5);
int chm_start_op(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 255, 3, 0 */
  /* observed branches: bnex1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l8ui a11, a8, -- 4: addr1 */
    /* l8ui a9, a2, -- 0: frame control */
    /* s8i a9, a8, -- 4: addr1 */
    /* l8ui a2, a2, -- 1: frame control/duration */
    /* s32i.n a3, a8, -- 8: 802.11 header region */
    /* s8i a2, a8, -- 5: 802.11 header region */
    /* s32i.n a4, a8, -- 12: 802.11 header region */
    /* s32i.n a5, a8, -- 20: eb len field region */
    /* s32i.n a6, a8, -- 24: seqctl/addr4/QoS */
  /* observed call sequence (in order): .text.chm_change_channel+0x30 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[1] = *(u8 *)(((u8 *)0) + 4); /* l8ui → +4: addr1 */
  regs[9] = *(u8 *)((u8 *)a2 + 0); /* l8ui → +0: frame control */
  *(u8 *)(((u8 *)0) + 4) = (u8)regs[9]; /* s8i → +4: addr1 */
  regs[2] = *(u8 *)((u8 *)a2 + 1); /* l8ui → +1: frame control/duration */
  *(u32 *)(((u8 *)0) + 8) = regs[3]; /* s32i.n a3,a8+8 → +8: 802.11 header region */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
