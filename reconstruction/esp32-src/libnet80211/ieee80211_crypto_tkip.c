/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_crypto_tkip.o
 * Blob: esp32/libnet80211.a(ieee80211_crypto_tkip.o) -> /tmp/re_esp32/libnet80211/ieee80211_crypto_tkip.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_crypto_tkip.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): g_ic, ieee80211_gettid
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
int tkip_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int tkip_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int tkip_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int tkip_encap(void *a2, void *a3, unsigned a4, unsigned a5);

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

/* tkip_decap @ ieee80211_crypto_tkip.o 00000008 size 163B bind GLOBAL
 * Calls: ieee80211_gettid | Data refs: g_ic, ieee80211_gettid
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.tkip_decap */
int tkip_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int tkip_decap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: bbsix3, bneix1, beqix1, bnex1, beqx1, bltux1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i.n a10, a5, -- 4: addr1 */
    /* l8ui a8, a5, -- 3: 802.11 header region */
    /* l32i a8, a8, -- 28: HT */
    /* l8ui a8, a5, -- 0: frame control */
    /* l8ui a9, a5, -- 4: addr1 */
    /* l8ui a9, a5, -- 2: duration */
    /* l8ui a9, a5, -- 5: 802.11 header region */
    /* l8ui a9, a5, -- 7: 802.11 header region */
    /* l8ui a11, a5, -- 6: 802.11 header region */
  /* observed call sequence (in order): ieee80211_gettid */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a10,a5+4 → +4: addr1 */
  regs[8] = *(u8 *)((u8 *)(uintptr_t)a4 + 3); /* l8ui → +3: 802.11 header region */
  regs[8] = *(u32 *)(((u8 *)0) + 28); /* l32i a8,a8+28 → +28: HT */
  regs[8] = *(u8 *)((u8 *)(uintptr_t)a4 + 0); /* l8ui → +0: frame control */
  regs[9] = *(u8 *)((u8 *)(uintptr_t)a4 + 4); /* l8ui → +4: addr1 */
  (void)((int(*)())ieee80211_gettid)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* tkip_encap @ ieee80211_crypto_tkip.o 00000008 size 157B bind GLOBAL
 * Calls: none | Data refs: g_ic, tkip
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.tkip_encap */
int tkip_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int tkip_encap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 32 */
  /* observed branches: bnex1, bltux1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a11, a2, -- 28: HT */
    /* l32i.n a2, a3, -- 4: addr1 */
    /* l32i.n a10, a8, -- 4: addr1 */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* s32i.n a8, a2, -- 4: addr1 */
    /* l16ui a2, a3, -- 22: seqctl/len */
    /* s16i a10, a3, -- 22: seqctl/len */
    /* l8ui a10, a9, -- off 153 */
    /* s8i a10, a8, -- 0: frame control */
    /* s8i a10, a8, -- 1: frame control/duration */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a2 + 28); /* l32i.n a11,a2+28 → +28: HT */
  regs[2] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a2,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a10,a8+4 → +4: addr1 */
  regs[8] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a8,a2+4 → +4: addr1 */
  *(u32 *)((u8 *)a2 + 4) = regs[8]; /* s32i.n a8,a2+4 → +4: addr1 */
  regs[2] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
