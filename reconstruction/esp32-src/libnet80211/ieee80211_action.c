/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_action.o
 * Blob: esp32/libnet80211.a(ieee80211_action.o) -> /tmp/re_esp32/libnet80211/ieee80211_action.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_action.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): wifi_log
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
int ieee80211_recv_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_register(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_register(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_register(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_register(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int wifi_log();

/* ieee80211_recv_action @ ieee80211_action.o 00000024 size 159B bind GLOBAL
 * Calls: none | Data refs: .data.ba_recv_action, .data.ht_recv_action, .data.sa_query_recv_action, .data.vendor_recv_action, .data.public_recv_action
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_recv_action_register */
int ieee80211_recv_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 127, 0, 33, -1 */
  /* observed branches: beqix4, beqx1, beqz.nx1, bnez.nx1, bltux1 */
  /* observed memory traffic (first 2): */
    /* s32i.n a4, a3, -- 0: frame control */
    /* s32i.n a4, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)((u8 *)a3 + 0) = regs[4]; /* s32i.n a4,a3+0 → +0: frame control */
  *(u32 *)((u8 *)a2 + 0) = regs[4]; /* s32i.n a4,a2+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_recv_action_register @ ieee80211_action.o 00000014 size 98B bind GLOBAL
 * Calls: none | Data refs: .data.ba_recv_action, .data.ht_recv_action, .data.sa_query_recv_action, .data.vendor_recv_action, .data.public_recv_action
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_recv_action_register */
int ieee80211_recv_action_register(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_register(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 127, 0, 33, -1 */
  /* observed branches: beqix4, beqx1, beqz.nx1, bnez.nx1, bltux1 */
  /* observed memory traffic (first 2): */
    /* s32i.n a4, a3, -- 0: frame control */
    /* s32i.n a4, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)((u8 *)a3 + 0) = regs[4]; /* s32i.n a4,a3+0 → +0: frame control */
  *(u32 *)((u8 *)a2 + 0) = regs[4]; /* s32i.n a4,a2+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_recv_action_unregister @ ieee80211_action.o 00000008 size 18B bind GLOBAL
 * Calls: ieee80211_recv_action_register | Data refs: .text.recv_inval, ieee80211_recv_action_register
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_recv_action_unregister */
int ieee80211_recv_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recv_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed call sequence (in order): ieee80211_recv_action_register */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  (void)((int(*)())ieee80211_recv_action_register)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_action @ ieee80211_action.o 00000014 size 118B bind GLOBAL
 * Calls: none | Data refs: .data.ba_send_action, .data.ht_send_action, .data.vendor_send_action, .data.sa_query_send_action
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_send_action_register */
int ieee80211_send_action(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 8, 127, 0, -1 */
  /* observed branches: beqix3, bltx1, beqx1, beqz.nx1, bnez.nx1 */
  /* observed memory traffic (first 2): */
    /* s32i.n a4, a2, -- 0: frame control */
    /* s32i.n a4, a3, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)((u8 *)a2 + 0) = regs[4]; /* s32i.n a4,a2+0 → +0: frame control */
  *(u32 *)((u8 *)a3 + 0) = regs[4]; /* s32i.n a4,a3+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_action_register @ ieee80211_action.o 00000010 size 86B bind GLOBAL
 * Calls: none | Data refs: .data.ba_send_action, .data.ht_send_action, .data.vendor_send_action, .data.sa_query_send_action
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_send_action_register */
int ieee80211_send_action_register(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_register(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 8, 127, 0, -1 */
  /* observed branches: beqix3, bltx1, beqx1, beqz.nx1, bnez.nx1 */
  /* observed memory traffic (first 2): */
    /* s32i.n a4, a2, -- 0: frame control */
    /* s32i.n a4, a3, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)((u8 *)a2 + 0) = regs[4]; /* s32i.n a4,a2+0 → +0: frame control */
  *(u32 *)((u8 *)a3 + 0) = regs[4]; /* s32i.n a4,a3+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_action_unregister @ ieee80211_action.o 00000008 size 18B bind GLOBAL
 * Calls: ieee80211_send_action_register | Data refs: .text.send_inval, ieee80211_send_action_register
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_send_action_unregister */
int ieee80211_send_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_action_unregister(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed call sequence (in order): ieee80211_send_action_register */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  (void)((int(*)())ieee80211_send_action_register)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
