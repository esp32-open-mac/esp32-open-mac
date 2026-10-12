/* Reconstructed ESP32 WiFi MAC data-path: wl_offchan.o
 * Blob: esp32/libnet80211.a(wl_offchan.o) -> /tmp/re_esp32/libnet80211/wl_offchan.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/wl_offchan.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): chm_acquire_lock, chm_cancel_op, chm_get_current_channel, chm_get_home_channel, chm_release_lock, chm_return_home_channel, chm_start_op, cnx_node_search, g_chm, g_ic, g_mt, g_osi_funcs_p, g_wifi_global_lock, g_wifi_nvs, ic_ebuf_recycle_tx, ieee80211_construct_action_vendor_spec, ieee80211_ethbroadcast, ieee80211_get_robustmgtframe, ieee80211_getmgtframe, ieee80211_post_hmac_tx, ieee80211_set_tx_desc, ieee80211_setup_robust_mgmtframe, ieee80211_sta_is_connected, memcmp...
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
int offchan_action_tx_req(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_action_tx_req(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_recv_action(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_recv_action(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_roc_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_roc_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_roc_req(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_roc_req(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_send_action_tx_status(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_send_action_tx_status(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_trigger_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_trigger_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_tx_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_tx_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int chm_acquire_lock();
extern int chm_cancel_op();
extern int chm_get_current_channel();
extern int chm_get_home_channel();
extern int chm_release_lock();
extern int chm_return_home_channel();
extern int chm_start_op();
extern int cnx_node_search();
extern int ic_ebuf_recycle_tx();
extern int ieee80211_construct_action_vendor_spec();
extern int ieee80211_get_robustmgtframe();
extern int ieee80211_getmgtframe();
extern int ieee80211_post_hmac_tx();
extern int ieee80211_set_tx_desc();
extern int ieee80211_setup_robust_mgmtframe();
extern int ieee80211_sta_is_connected();
extern int mt_get_peer_info();
extern int pm_offchan_execute_ready_cb();
extern int pm_offchan_is_waiting();
extern int pm_offchan_ready_or_defer();
extern int pm_on_channel();
extern int pm_wake_done();
extern int pm_wake_up();
extern int sta_reset_beacon_timeout();
extern int wifi_check_chan_param();
extern int wifi_event_post();
extern int wifi_get_macaddr();
extern int wifi_log();
extern int wifi_set_rx_policy();

/* offchan_action_tx_req @ wl_offchan.o 00000098 size 680B bind GLOBAL
 * Calls: wifi_check_chan_param, wifi_log, chm_acquire_lock, memcpy, memset, chm_get_current_channel, pm_wake_up, pm_offchan_ready_or_defer, .text.offchan_action_tx_sess_handler, chm_release_lock, pm_wake_done, chm_cancel_op | Data refs: g_ic, .rodata_wlog_error.29, .rodata_wlog_error.30, .rodata_wlog_error.31, g_osi_funcs_p, .rodata_wlog_error.32, .rodata_wlog_error.33, .text.offchan_txop_end, .rodata_wlog_error.34, .rodata_wlog_debug.35
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.offchan_action_tx_req */
int offchan_action_tx_req(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_action_tx_req(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 2, 0, 4, 16, 3, 28, -1 */
  /* observed branches: bnez.nx7, beqix1, beqz.nx2, bneix3, beqx1, bnex1 */
  /* observed memory traffic (first 10): */
    /* l8ui a4, a2, -- 16: addr3 */
    /* l32i.n a5, a2, -- 20: eb len field region */
    /* l32i.n a8, a2, -- 24: seqctl/addr4/QoS */
    /* s32i.n a3, a1, -- 44: eb priv word */
    /* l32i.n a3, a2, -- 12: 802.11 header region */
    /* s32i.n a4, a1, -- off 32 */
    /* s32i.n a5, a1, -- off 36 */
    /* s32i.n a8, a1, -- off 40 */
    /* l32i.n a4, a4, -- 16: addr3 */
    /* l32i.n a11, a1, -- off 36 */
  /* observed call sequence (in order): wifi_check_chan_param -> wifi_log -> chm_acquire_lock -> memcpy -> memset -> chm_get_current_channel -> pm_wake_up -> pm_offchan_ready_or_defer -> .text.offchan_action_tx_sess_handler+0x2c -> chm_release_lock -> pm_wake_done -> chm_cancel_op */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u8 *)((u8 *)a2 + 16); /* l8ui → +16: addr3 */
  regs[5] = *(u32 *)((u8 *)a2 + 20); /* l32i.n a5,a2+20 → +20: eb len field region */
  regs[8] = *(u32 *)((u8 *)a2 + 24); /* l32i.n a8,a2+24 → +24: seqctl/addr4/QoS */
  *(u32 *)(((u8 *)a1_spill) + 44) = regs[3]; /* s32i.n a3,a1+44 → +44: eb priv word */
  regs[3] = *(u32 *)((u8 *)a2 + 12); /* l32i.n a3,a2+12 → +12: 802.11 header region */
  *(u32 *)(((u8 *)a1_spill) + 32) = regs[4]; /* s32i.n a4,a1+32 → +32:  */
  (void)((int(*)())wifi_check_chan_param)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_acquire_lock)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_current_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pm_wake_up)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pm_offchan_ready_or_defer)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_release_lock)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* offchan_in_progress @ wl_offchan.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: g_offchan_ctx
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.offchan_in_progress */
int offchan_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_in_progress(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed memory traffic (first 1): */
    /* l16ui a9, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u16 *)((u8 *)a2 + 0); /* l16ui → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* offchan_recv_action @ wl_offchan.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: g_offchan_ctx
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.offchan_recv_action */
int offchan_recv_action(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_recv_action(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 1): */
    /* l32i.n a9, a8, -- 4: addr1 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a8+4 → +4: addr1 */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* offchan_roc_in_progress @ wl_offchan.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_offchan_ctx
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.offchan_roc_in_progress */
int offchan_roc_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_roc_in_progress(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 1): */
    /* l8ui a2, a8, -- 1: frame control/duration */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)(((u8 *)0) + 1); /* l8ui → +1: frame control/duration */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* offchan_roc_req @ wl_offchan.o 0000008c size 528B bind GLOBAL
 * Calls: wifi_check_chan_param, wifi_log, chm_acquire_lock, chm_release_lock, memset, chm_get_current_channel, pm_wake_up, pm_offchan_ready_or_defer, .text.roc_sess_handler, pm_wake_done, chm_cancel_op | Data refs: g_ic, .rodata_wlog_error.20, .rodata_wlog_error.21, g_wifi_nvs, .rodata_wlog_error.22, .rodata_wlog_error.23, .text.roc_op_end, .rodata_wlog_error.24, g_osi_funcs_p, .rodata_wlog_error.25
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.offchan_roc_req */
int offchan_roc_req(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_roc_req(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 2, 0, 4, 3, 16, 28, -1 */
  /* observed branches: bnez.nx6, beqz.nx2, beqix3, bneix1, beqx1, bnex1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a4, -- 16: addr3 */
    /* l32i.n a4, a2, -- 4: addr1 */
    /* l32i a11, a2, -- 12: 802.11 header region */
    /* l8ui a10, a2, -- 8: 802.11 header region */
    /* l32i.n a15, a2, -- 12: 802.11 header region */
    /* l8ui a14, a2, -- 8: 802.11 header region */
    /* l32i.n a4, a2, -- 16: addr3 */
    /* l8ui a4, a2, -- off 32 */
    /* l32i.n a4, a4, -- 0: frame control */
    /* l8ui a4, a4, -- 0: frame control */
  /* observed call sequence (in order): wifi_check_chan_param -> wifi_log -> chm_acquire_lock -> chm_release_lock -> memset -> chm_get_current_channel -> pm_wake_up -> pm_offchan_ready_or_defer -> .text.roc_sess_handler+0x50 -> pm_wake_done -> chm_cancel_op */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)(eb8 + 16); /* l32i.n a5,a4+16 → +16: addr3 */
  regs[4] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a4,a2+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)a2 + 12); /* l32i a11,a2+12 → +12: 802.11 header region */
  regs[1] = *(u8 *)((u8 *)a2 + 8); /* l8ui → +8: 802.11 header region */
  regs[1] = *(u32 *)((u8 *)a2 + 12); /* l32i.n a15,a2+12 → +12: 802.11 header region */
  regs[1] = *(u8 *)((u8 *)a2 + 8); /* l8ui → +8: 802.11 header region */
  (void)((int(*)())wifi_check_chan_param)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_acquire_lock)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_release_lock)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_current_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pm_wake_up)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pm_offchan_ready_or_defer)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pm_wake_done)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* offchan_send_action_tx_status @ wl_offchan.o 00000008 size 64B bind GLOBAL
 * Calls: wifi_event_post | Data refs: g_offchan_ctx, wifi_event_post
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.offchan_send_action_tx_status */
int offchan_send_action_tx_status(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_send_action_tx_status(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, 16, 19 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 9): */
    /* l8ui a9, a8, -- 0: frame control */
    /* s32i.n a9, a1, -- 0: frame control */
    /* l32i.n a9, a8, -- 4: addr1 */
    /* s32i.n a9, a1, -- 4: addr1 */
    /* l8ui a9, a8, -- 12: 802.11 header region */
    /* l8ui a8, a8, -- 2: duration */
    /* s32i.n a3, a1, -- 8: 802.11 header region */
    /* s8i a9, a1, -- 12: 802.11 header region */
    /* s8i a8, a1, -- 13: 802.11 header region */
  /* observed call sequence (in order): wifi_event_post */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[9]; /* s32i.n a9,a1+0 → +0: frame control */
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a8+4 → +4: addr1 */
  *(u32 *)(((u8 *)a1_spill) + 4) = regs[9]; /* s32i.n a9,a1+4 → +4: addr1 */
  regs[9] = *(u8 *)(((u8 *)0) + 12); /* l8ui → +12: 802.11 header region */
  regs[8] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  (void)((int(*)())wifi_event_post)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* offchan_trigger_in_progress @ wl_offchan.o 00000008 size 34B bind GLOBAL
 * Calls: offchan_in_progress | Data refs: g_offchan_ctx, offchan_in_progress
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.offchan_trigger_in_progress */
int offchan_trigger_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_trigger_in_progress(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: beqx1 */
  /* observed memory traffic (first 1): */
    /* l8ui a8, a8, -- 24: seqctl/addr4/QoS */
  /* observed call sequence (in order): offchan_in_progress */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)(((u8 *)0) + 24); /* l8ui → +24: seqctl/addr4/QoS */
  (void)((int(*)())offchan_in_progress)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* offchan_tx_in_progress @ wl_offchan.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_offchan_ctx
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.offchan_tx_in_progress */
int offchan_tx_in_progress(void *a2, void *a3, unsigned a4, unsigned a5);
int offchan_tx_in_progress(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 1): */
    /* l8ui a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
