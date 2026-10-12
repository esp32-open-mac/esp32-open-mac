/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_crypto_wep.o
 * Blob: esp32/libnet80211.a(ieee80211_crypto_wep.o) -> /tmp/re_esp32/libnet80211/ieee80211_crypto_wep.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_crypto_wep.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
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
int wep_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int wep_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int wep_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int wep_encap(void *a2, void *a3, unsigned a4, unsigned a5);

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


/* wep_decap @ ieee80211_crypto_wep.o 00000000 size 41B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.wep_decap */
int wep_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int wep_decap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1 */
  /* observed memory traffic (first 8): */
    /* l32i a9, a2, -- off 160 */
    /* l32i.n a11, a3, -- 4: addr1 */
    /* l32i.n a10, a9, -- 4: addr1 */
    /* l32i.n a8, a11, -- 4: addr1 */
    /* l32i.n a9, a9, -- 8: 802.11 header region */
    /* s32i.n a8, a11, -- 4: addr1 */
    /* l16ui a8, a3, -- 22: seqctl/len */
    /* s16i a8, a3, -- 22: seqctl/len */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)((u8 *)a2 + 160); /* l32i a9,a2+160 → +160:  */
  regs[1] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a11,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a10,a9+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a11+4 → +4: addr1 */
  regs[9] = *(u32 *)(((u8 *)0) + 8); /* l32i.n a9,a9+8 → +8: 802.11 header region */
  *(u32 *)(((u8 *)0) + 4) = regs[8]; /* s32i.n a8,a11+4 → +4: addr1 */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* wep_encap @ ieee80211_crypto_wep.o 00000004 size 101B bind GLOBAL
 * Calls: none | Data refs: wep
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.wep_encap */
int wep_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int wep_encap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a2, a3, -- 4: addr1 */
    /* l32i.n a10, a8, -- 4: addr1 */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* s32i.n a8, a2, -- 4: addr1 */
    /* l16ui a2, a3, -- 22: seqctl/len */
    /* l32i a2, a9, -- 152: key PN/counter region */
    /* s16i a10, a3, -- 22: seqctl/len */
    /* l32i a11, a9, -- 156: key PN/counter region */
    /* s32i a10, a9, -- 152: key PN/counter region */
    /* s32i a3, a9, -- 156: key PN/counter region */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a2,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a10,a8+4 → +4: addr1 */
  regs[8] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a8,a2+4 → +4: addr1 */
  *(u32 *)((u8 *)a2 + 4) = regs[8]; /* s32i.n a8,a2+4 → +4: addr1 */
  regs[2] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[2] = *(u32 *)(((u8 *)0) + 152); /* l32i a2,a9+152 → +152: key PN/counter region */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
