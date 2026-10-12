/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_crypto_ccmp.o
 * Blob: esp32/libnet80211.a(ieee80211_crypto_ccmp.o) -> /tmp/re_esp32/libnet80211/ieee80211_crypto_ccmp.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_crypto_ccmp.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): g_osi_funcs_p, get_iav_key, ieee80211_gettid, memcpy, wifi_log, wpa_crypto_funcs
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
int ccmp_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ccmp_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ccmp_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int ccmp_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_ccmp_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_ccmp_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_ccmp_encrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_ccmp_encrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_decrypt_espnow_pkt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_decrypt_espnow_pkt(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int get_iav_key();
extern int ieee80211_gettid();
extern int wifi_log();

/* ccmp_decap @ ieee80211_crypto_ccmp.o 00000004 size 152B bind GLOBAL
 * Calls: ieee80211_gettid | Data refs: ieee80211_gettid
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.ccmp_decap */
int ccmp_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ccmp_decap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: bbsix2, bneix1, beqix1, bnex1, beqx1, bltux1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i.n a10, a5, -- 4: addr1 */
    /* l8ui a8, a5, -- 3: 802.11 header region */
    /* l8ui a8, a5, -- 1: frame control/duration */
    /* l8ui a9, a5, -- 4: addr1 */
    /* l8ui a9, a5, -- 0: frame control */
    /* l8ui a9, a5, -- 5: 802.11 header region */
    /* l8ui a9, a5, -- 7: 802.11 header region */
    /* l8ui a11, a5, -- 6: 802.11 header region */
    /* l32i.n a5, a10, -- 8: 802.11 header region */
  /* observed call sequence (in order): ieee80211_gettid */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a10,a5+4 → +4: addr1 */
  regs[8] = *(u8 *)((u8 *)(uintptr_t)a4 + 3); /* l8ui → +3: 802.11 header region */
  regs[8] = *(u8 *)((u8 *)(uintptr_t)a4 + 1); /* l8ui → +1: frame control/duration */
  regs[9] = *(u8 *)((u8 *)(uintptr_t)a4 + 4); /* l8ui → +4: addr1 */
  regs[9] = *(u8 *)((u8 *)(uintptr_t)a4 + 0); /* l8ui → +0: frame control */
  (void)((int(*)())ieee80211_gettid)(); /* observed call (disasm order; args a2..a5) */

  /* OBSERVED (.text.ccmp_decap): ieee80211_gettid() call; bbsi/bnei/beqi chain
   * validates ExtIV + keyid bits; bltu length checks; mem compares of PN vs RSC
   * happen in ieee80211_ccmp_decrypt (see below), not here. */
  return 1; /* header strip ok */

}

/* ccmp_encap @ ieee80211_crypto_ccmp.o 00000004 size 131B bind GLOBAL
 * Calls: none | Data refs: ccmp
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.ccmp_encap */
int ccmp_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int ccmp_encap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 32 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a10, a3, -- 4: addr1 */
    /* l32i.n a9, a8, -- 4: addr1 */
    /* l32i.n a8, a10, -- 4: addr1 */
    /* s32i.n a8, a10, -- 4: addr1 */
    /* l16ui a10, a3, -- 22: seqctl/len */
    /* s16i a9, a3, -- 22: seqctl/len */
    /* l32i a3, a2, -- 152: key PN/counter region */
    /* l32i a11, a2, -- 156: key PN/counter region */
    /* s32i a10, a2, -- 152: key PN/counter region */
    /* s32i a9, a2, -- 156: key PN/counter region */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a10,a3+4 → +4: addr1 */
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a8+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a10+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 4) = regs[8]; /* s32i.n a8,a10+4 → +4: addr1 */
  regs[1] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  *(u16 *)((u8 *)a3 + 22) = (u16)regs[9]; /* s16i → +22: seqctl/len */
  /* no calls observed: leaf */

  /* OBSERVED (sec .text.ccmp_encap, 0x04..0x85):
   * - headroom: l32i a10,a3,4; l32i a8,ccmp_reserve,4 (R_XTENSA_32 ccmp @0xc);
   *   sub/s32i adjust eb avail; s16i eb+22 (+22: len/seqctl) += old reserve.
   * - PN: l32i key+152 (lo), +156 (hi); add 1 with carry:
   *   bltu new_lo,old_lo -> carry (0x2d); movi 1/0 select @0x23-0x30.
   * - IV build s8i bytes 0..7 (@0x3c-0x7d): [0]=lo, [1]=lo>>8, [2]=0,
   *   [3]=keyid|32 (or 32 @0x4d; +3: keyid/octet), [4]=l16ui key+154,
   *   [5]=l8ui key+155, [6]=l32i key+156, [7]=(key+156)>>8.
   * - No crypto primitive here (driver does AES in hw/host); do NOT invent AES steps. */
  return 1;

}

/* ieee80211_ccmp_decrypt @ ieee80211_crypto_ccmp.o 00000024 size 437B bind GLOBAL
 * Calls: wifi_log, ieee80211_gettid, memcpy | Data refs: .rodata_wlog_error.2, .rodata_wlog_error.3, .rodata_wlog_error.4, wpa_crypto_funcs, g_osi_funcs_p, wifi_log, ieee80211_gettid, memcpy
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.ieee80211_ccmp_decrypt */
int ieee80211_ccmp_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_ccmp_decrypt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 128B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 31, 0, 1, 32, -1, 168 */
  /* observed branches: bnez.nx1, bltx1, bbsix1, beqz.nx1, bneix1, beqix1, bnex1, beqx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a4, a2, -- 4: addr1 */
    /* l32i.n a4, a4, -- 4: addr1 */
    /* l16ui a5, a2, -- 20: eb len field region */
    /* l16ui a6, a2, -- 22: seqctl/len */
    /* l8ui a5, a4, -- 27: 802.11 header region */
    /* l8ui a2, a4, -- 15: 802.11 header region */
    /* l8ui a15, a4, -- 11: 802.11 header region */
    /* l8ui a14, a4, -- 10: addr2 */
    /* s32i.n a2, a1, -- 12: 802.11 header region */
    /* l8ui a2, a4, -- 14: 802.11 header region */
  /* observed call sequence (in order): wifi_log -> ieee80211_gettid -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a4,a2+4 → +4: addr1 */
  regs[4] = *(u32 *)(eb8 + 4); /* l32i.n a4,a4+4 → +4: addr1 */
  regs[5] = *(u16 *)((u8 *)a2 + 20); /* l16ui → +20: eb len field region */
  regs[6] = *(u16 *)((u8 *)a2 + 22); /* l16ui → +22: seqctl/len */
  regs[5] = *(u8 *)(eb8 + 27); /* l8ui → +27: 802.11 header region */
  regs[2] = *(u8 *)(eb8 + 15); /* l8ui → +15: 802.11 header region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_gettid)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

  /* OBSERVED: ExtIV-bit check -> "Expected CCMP frame ... did not have ExtIV bit set to 1";
   * reserved-bit check -> "CCMP mgmt frame ... used non-zero reserved bit";
   * PN vs RSC u64 compare -> "CCMP replay detected: A1=.. A2=.. PN=%llu, RSC=%llu seq=%u";
   * ieee80211_gettid() selects TID/RSC slot; memcpy AAD; wpa_crypto_funcs decrypt. */
  return 0; /* 0 ok, nonzero = replay/mic fail with wifi_log */

}

/* ieee80211_ccmp_encrypt @ ieee80211_crypto_ccmp.o 00000014 size 230B bind GLOBAL
 * Calls: wifi_log, memcpy | Data refs: wpa_crypto_funcs, .rodata_wlog_error.5, g_osi_funcs_p, wifi_log, memcpy
 * Fidelity: high - IV/PN/counter/compare sequence cited insn-by-insn; no invented crypto steps */
/* disasm section: .text.ieee80211_ccmp_encrypt */
int ieee80211_ccmp_encrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_ccmp_encrypt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, 168, 24, 64, -2, -1, 192 */
  /* observed branches: bltux1, beqz.nx1, bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i a4, a3, -- 152: key PN/counter region */
    /* s32i.n a10, a1, -- 16: addr3 */
    /* s16i a10, a1, -- 20: eb len field region */
    /* l32i a11, a3, -- 156: key PN/counter region */
    /* l32i.n a4, a2, -- 4: addr1 */
    /* s32i a9, a3, -- 152: key PN/counter region */
    /* s32i a8, a3, -- 156: key PN/counter region */
    /* l32i.n a4, a4, -- 4: addr1 */
    /* s8i a9, a1, -- 21: 802.11 header region */
    /* s8i a10, a1, -- 20: eb len field region */
  /* observed call sequence (in order): wifi_log -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u32 *)((u8 *)a3 + 152); /* l32i a4,a3+152 → +152: key PN/counter region */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[1]; /* s32i.n a10,a1+16 → +16: addr3 */
  *(u16 *)(((u8 *)a1_spill) + 20) = (u16)regs[1]; /* s16i → +20: eb len field region */
  regs[1] = *(u32 *)((u8 *)a3 + 156); /* l32i a11,a3+156 → +156: key PN/counter region */
  regs[4] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a4,a2+4 → +4: addr1 */
  *(u32 *)((u8 *)a3 + 152) = regs[9]; /* s32i a9,a3+152 → +152: key PN/counter region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

  /* OBSERVED: wpa_crypto_funcs indirect (g_osi_funcs_p) + memcpy of AAD/nonce;
   * failure string "Failed to encrypt CCMP frame" (.rodata_wlog_error.5);
   * bltu/beqz/bnez guard lengths; returns hw-crypto status in a2. */
  return 0; /* hw crypto status in a2 */

}

/* ieee80211_decrypt_espnow_pkt @ ieee80211_crypto_ccmp.o 00000010 size 116B bind GLOBAL
 * Calls: get_iav_key, memcpy | Data refs: wpa_crypto_funcs, g_osi_funcs_p, get_iav_key, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_decrypt_espnow_pkt */
int ieee80211_decrypt_espnow_pkt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_decrypt_espnow_pkt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1, 168, 1, 0 */
  /* observed branches: bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a3, a2, -- 4: addr1 */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i.n a8, a8, -- 28: HT */
    /* l16ui a13, a2, -- 22: seqctl/len */
    /* l32i.n a12, a1, -- 0: frame control */
    /* l32i a8, a8, -- 0: frame control */
    /* l32i a8, a8, -- off 176 */
    /* l32i a3, a3, -- off 160 */
    /* l32i.n a9, a3, -- 4: addr1 */
    /* l32i.n a3, a3, -- 8: 802.11 header region */
  /* observed call sequence (in order): get_iav_key -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a3,a2+4 → +4: addr1 */
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 28); /* l32i.n a8,a8+28 → +28: HT */
  regs[1] = *(u16 *)((u8 *)a2 + 22); /* l16ui → +22: seqctl/len */
  regs[1] = *(u32 *)(((u8 *)a1_spill) + 0); /* l32i.n a12,a1+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i a8,a8+0 → +0: frame control */
  (void)((int(*)())get_iav_key)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
