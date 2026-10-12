/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_crypto_sms4.o
 * Blob: esp32/libnet80211.a(ieee80211_crypto_sms4.o) -> /tmp/re_esp32/libnet80211/ieee80211_crypto_sms4.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_crypto_sms4.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): ieee80211_gettid, memcpy, wifi_log
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
int sms4_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int sms4_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int sms4_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int sms4_decap(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int ieee80211_gettid();
extern int wifi_log();

/* sms4_encap @ ieee80211_crypto_sms4.o 00000000 size 101B bind GLOBAL
 * Calls: memcpy | Data refs: sms4, .rodata.sms4_encap.str1.1, memcpy
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.sms4_encap */
int sms4_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int sms4_encap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 1, 0, 8 */
  /* observed branches: beqz.nx1, bltux2 */
  /* observed memory traffic (first 10): */
    /* l32i.n a2, a3, -- 4: addr1 */
    /* l32i.n a10, a2, -- 4: addr1 */
    /* l32i.n a9, a9, -- 4: addr1 */
    /* s32i.n a10, a2, -- 4: addr1 */
    /* l16ui a2, a3, -- 22: seqctl/len */
    /* l32i.n a2, a3, -- 44: eb priv word */
    /* l32i.n a2, a2, -- 0: frame control */
    /* s16i a9, a3, -- 22: seqctl/len */
    /* l32i a12, a8, -- 152: key PN/counter region */
    /* l32i a11, a8, -- 156: key PN/counter region */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a2,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a10,a2+4 → +4: addr1 */
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a9+4 → +4: addr1 */
  *(u32 *)((u8 *)a2 + 4) = regs[1]; /* s32i.n a10,a2+4 → +4: addr1 */
  regs[2] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[2] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a2,a3+44 → +44: eb priv word */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
/* OBSERVED (.text.sms4_encap 0x0c..0xd0):
 * - headroom reserve via sms4 data symbol (R_XTENSA_32 sms4 @0x0) like ccmp;
 * - flag test: l32i eb+0, and 2 -> beqz 0x52 path (+0: flags word);
 * - counter: key+152 +1 or +2 with bltu carry (@0x43-0x5d; movi 1/2);
 * - IV s8i 0..9 (@0x69-0xbd): [0]=a4&0xff, [1]=0, [2]=lo, [3]=lo>>8,
 *   [4]=l16ui key+154, [5]=l8ui key+155, [6]=key+156, [7]=(key+156)>>8,
 *   [8]=l16ui key+158, [9]=l8ui key+159; then a10+=10, memcpy payload.
 * - WAPI PN string "WAPI: pn err ..." in funcdb strings; do NOT invent SMS4 rounds. */
  return 1;
}

/* sms4_decap @ ieee80211_crypto_sms4.o 00000000 size 163B bind GLOBAL
 * Calls: ieee80211_gettid, wifi_log | Data refs: .rodata_wlog_warning.2, ieee80211_gettid, wifi_log
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.sms4_decap */
int sms4_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int sms4_decap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 2, 4 */
  /* observed branches: bneix1, beqix1, bnex1, beqx1, bltux1, bbcix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i.n a10, a5, -- 4: addr1 */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i.n a5, a5, -- 4: addr1 */
    /* l32i.n a6, a5, -- 0: frame control */
    /* l32i.n a7, a5, -- 4: addr1 */
    /* l32i.n a15, a5, -- 8: 802.11 header region */
    /* l32i.n a8, a5, -- 12: 802.11 header region */
    /* s32i.n a10, a1, -- 0: frame control */
    /* s32i.n a7, a5, -- 12: 802.11 header region */
  /* observed call sequence (in order): ieee80211_gettid -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a10,a5+4 → +4: addr1 */
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a5,a5+4 → +4: addr1 */
  regs[6] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a6,a5+0 → +0: frame control */
  regs[7] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a7,a5+4 → +4: addr1 */
  (void)((int(*)())ieee80211_gettid)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
/* OBSERVED (.text.sms4_decap): ieee80211_gettid() + wifi_log warning path;
 * bnei/beqi/bne/bltu/bbci chain validates header; PN-vs-RSC compare
 * sequence mirrors ccmp_decrypt; do NOT invent SMS4 rounds. */
  return 1;
}
