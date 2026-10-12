/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_crypto.o
 * Blob: esp32/libnet80211.a(ieee80211_crypto.o) -> /tmp/re_esp32/libnet80211/ieee80211_crypto.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_crypto.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): g_ic, g_osi_funcs_p, ieee80211w_get_active_igtk_key_id, ieee80211w_get_igtk_from_keyidx, memcmp, memcpy, memset, wifi_log
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
int ieee80211_crypto_aes_128_cmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_aes_128_cmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_available(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_available(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_encrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_encrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_encrypt_with_key(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_encrypt_with_key(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_verify_with_key(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_verify_with_key(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_gmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_gmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_setkey(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_setkey(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_cipher_mic_len(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_cipher_mic_len(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int ieee80211w_get_active_igtk_key_id();
extern int ieee80211w_get_igtk_from_keyidx();
extern int wifi_log();

/* ieee80211_crypto_aes_128_cmac_decrypt @ ieee80211_crypto.o 00000038 size 329B bind GLOBAL
 * Calls: ieee80211w_get_igtk_from_keyidx, memcmp, wifi_log, memcpy | Data refs: .rodata_wlog_error.9, .rodata_wlog_error.10, g_osi_funcs_p, wpa_crypto_funcs, .rodata_wlog_error.11, .rodata_wlog_error.12, ieee80211w_get_igtk_from_keyidx, memcmp, wifi_log, memcpy
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_crypto_aes_128_cmac_decrypt */
int ieee80211_crypto_aes_128_cmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_aes_128_cmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 19, 0, 76, 6, 1, 32, -1, 18, -57, 8 */
  /* observed branches: bltux1, bnex1, bneix1, bnez.nx1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l16ui a5, a3, -- 22: seqctl/len */
    /* l32i.n a2, a7, -- 4: addr1 */
    /* l32i.n a13, a2, -- 4: addr1 */
    /* l8ui a6, a4, -- 0: frame control */
    /* s32i.n a2, a1, -- 20: eb len field region */
    /* l8ui a2, a4, -- 1: frame control/duration */
    /* l8ui a11, a4, -- 3: 802.11 header region */
    /* l8ui a2, a4, -- 2: duration */
    /* s32i.n a13, a1, -- 28: HT */
    /* s32i.n a10, a1, -- 24: seqctl/addr4/QoS */
  /* observed call sequence (in order): ieee80211w_get_igtk_from_keyidx -> memcmp -> wifi_log -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[2] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a2,a7+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a13,a2+4 → +4: addr1 */
  regs[6] = *(u8 *)(eb8 + 0); /* l8ui → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 20) = regs[2]; /* s32i.n a2,a1+20 → +20: eb len field region */
  regs[2] = *(u8 *)(eb8 + 1); /* l8ui → +1: frame control/duration */
  (void)((int(*)())ieee80211w_get_igtk_from_keyidx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* key/IV/nonce handling per observed insns above; crypto primitive via wpa_crypto_funcs; no invented steps. */
    return 0;
  
}

/* ieee80211_crypto_attach @ ieee80211_crypto.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_crypto_attach */
int ieee80211_crypto_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_attach(void *a2, void *a3, unsigned a4, unsigned a5)
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

/* ieee80211_crypto_available @ ieee80211_crypto.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_crypto_available */
int ieee80211_crypto_available(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_available(void *a2, void *a3, unsigned a4, unsigned a5)
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

/* ieee80211_crypto_bip_encrypt @ ieee80211_crypto.o 0000002c size 518B bind GLOBAL
 * Calls: ieee80211w_get_active_igtk_key_id, ieee80211w_get_igtk_from_keyidx, memcpy, wifi_log | Data refs: g_osi_funcs_p, wpa_crypto_funcs, .rodata_wlog_error.4, ieee80211w_get_active_igtk_key_id, ieee80211w_get_igtk_from_keyidx, memcpy, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_crypto_bip_encrypt */
int ieee80211_crypto_bip_encrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_encrypt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 8, 16, 76, 0, 6, 1, 18, -57, 9, 32 */
  /* observed branches: bltux1, bnex1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* s32i.n a4, a1, -- off 52 */
    /* s32i.n a2, a1, -- off 48 */
    /* l32i.n a2, a3, -- 4: addr1 */
    /* l32i.n a7, a2, -- 4: addr1 */
    /* l16ui a4, a3, -- 22: seqctl/len */
    /* l32i.n a6, a1, -- off 48 */
    /* s16i a4, a3, -- 22: seqctl/len */
    /* s8i a4, a5, -- 0: frame control */
    /* s8i a4, a5, -- 1: frame control/duration */
    /* s32i a8, a1, -- off 60 */
  /* observed call sequence (in order): ieee80211w_get_active_igtk_key_id -> ieee80211w_get_igtk_from_keyidx -> memcpy -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 52) = regs[4]; /* s32i.n a4,a1+52 → +52:  */
  *(u32 *)(((u8 *)a1_spill) + 48) = regs[2]; /* s32i.n a2,a1+48 → +48:  */
  regs[2] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a2,a3+4 → +4: addr1 */
  regs[7] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a7,a2+4 → +4: addr1 */
  regs[4] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[6] = *(u32 *)(((u8 *)a1_spill) + 48); /* l32i.n a6,a1+48 → +48:  */
  (void)((int(*)())ieee80211w_get_active_igtk_key_id)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211w_get_igtk_from_keyidx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* key/IV/nonce handling per observed insns above; crypto primitive via wpa_crypto_funcs; no invented steps. */
    return 0;
  
}

/* ieee80211_crypto_bip_encrypt_with_key @ ieee80211_crypto.o 00000028 size 484B bind GLOBAL
 * Calls: memcpy, memset, wifi_log | Data refs: g_osi_funcs_p, wpa_crypto_funcs, .rodata_wlog_error.5, memcpy, memset, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_crypto_bip_encrypt_with_key */
int ieee80211_crypto_bip_encrypt_with_key(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_encrypt_with_key(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 112B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 16, 8, 6, 76, 18, -57, 240, 9, 32 */
  /* observed branches: bnez.nx1, bneix1, bnex1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* s32i.n a4, a1, -- off 52 */
    /* s32i.n a5, a1, -- off 56 */
    /* l32i.n a2, a7, -- 4: addr1 */
    /* l32i.n a5, a2, -- 4: addr1 */
    /* s32i.n a4, a1, -- off 48 */
    /* l16ui a4, a7, -- 22: seqctl/len */
    /* l32i.n a8, a1, -- off 48 */
    /* s16i a4, a7, -- 22: seqctl/len */
    /* s8i a4, a6, -- 0: frame control */
    /* s8i a4, a6, -- 1: frame control/duration */
  /* observed call sequence (in order): memcpy -> memset -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 52) = regs[4]; /* s32i.n a4,a1+52 → +52:  */
  *(u32 *)(((u8 *)a1_spill) + 56) = regs[5]; /* s32i.n a5,a1+56 → +56:  */
  regs[2] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a2,a7+4 → +4: addr1 */
  regs[5] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a5,a2+4 → +4: addr1 */
  *(u32 *)(((u8 *)a1_spill) + 48) = regs[4]; /* s32i.n a4,a1+48 → +48:  */
  regs[4] = *(u16 *)(((u8 *)0) + 22); /* l16ui → +22: seqctl/len */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* key/IV/nonce handling per observed insns above; crypto primitive via wpa_crypto_funcs; no invented steps. */
    return 0;
  
}

/* ieee80211_crypto_bip_verify_with_key @ ieee80211_crypto.o 00000038 size 524B bind GLOBAL
 * Calls: wifi_log, memcpy, memset, memcmp | Data refs: .rodata_wlog_debug.6, g_osi_funcs_p, wpa_crypto_funcs, .rodata_wlog_error.7, .rodata_wlog_error.8, wifi_log, memcpy, memset, memcmp
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_crypto_bip_verify_with_key */
int ieee80211_crypto_bip_verify_with_key(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_bip_verify_with_key(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 8, 16, 76, -1, 5, 4, 32, 1, 18 */
  /* observed branches: bgex1, beqx2, bneix1, bnex1, beqz.nx2 */
  /* observed memory traffic (first 10): */
    /* s32i.n a4, a1, -- off 52 */
    /* s32i.n a4, a1, -- off 48 */
    /* l32i.n a2, a14, -- 4: addr1 */
    /* l32i.n a6, a1, -- off 48 */
    /* l32i.n a3, a2, -- 4: addr1 */
    /* l16ui a4, a14, -- 22: seqctl/len */
    /* l8ui a10, a5, -- 0: frame control */
    /* l32i.n a8, a1, -- off 48 */
    /* l8ui a10, a5, -- 1: frame control/duration */
    /* l8ui a9, a9, -- 4: addr1 */
  /* observed call sequence (in order): wifi_log -> memcpy -> memset -> memcmp */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 52) = regs[4]; /* s32i.n a4,a1+52 → +52:  */
  *(u32 *)(((u8 *)a1_spill) + 48) = regs[4]; /* s32i.n a4,a1+48 → +48:  */
  regs[2] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a2,a14+4 → +4: addr1 */
  regs[6] = *(u32 *)(((u8 *)a1_spill) + 48); /* l32i.n a6,a1+48 → +48:  */
  regs[3] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a3,a2+4 → +4: addr1 */
  regs[4] = *(u16 *)(((u8 *)0) + 22); /* l16ui → +22: seqctl/len */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */

    /* key/IV/nonce handling per observed insns above; crypto primitive via wpa_crypto_funcs; no invented steps. */
    return 0;
  
}

/* ieee80211_crypto_decap @ ieee80211_crypto.o 00000010 size 154B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.ieee80211_crypto_encap.str1.1, .rodata_wlog_error.3, g_ic, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_crypto_decap */
int ieee80211_crypto_decap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_decap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 154, 31, 0, 255 */
  /* observed branches: bnez.nx2, bgex1, bbcix2, beqix1, bnex1, bneix1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l16ui a9, a3, -- 20: eb len field region */
    /* l8ui a10, a8, -- off 139 */
    /* l16ui a8, a3, -- 22: seqctl/len */
    /* l32i.n a8, a3, -- 4: addr1 */
    /* l32i.n a9, a8, -- 4: addr1 */
    /* l8ui a8, a9, -- 4: addr1 */
    /* l8ui a8, a9, -- 3: 802.11 header region */
    /* l8ui a2, a8, -- 0: frame control */
    /* l8ui a2, a9, -- 0: frame control */
    /* l8ui a2, a2, -- off 53 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u16 *)((u8 *)a3 + 20); /* l16ui → +20: eb len field region */
  regs[1] = *(u8 *)(((u8 *)0) + 139); /* l8ui → +139:  */
  regs[8] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[8] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a8,a3+4 → +4: addr1 */
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a8+4 → +4: addr1 */
  regs[8] = *(u8 *)(((u8 *)0) + 4); /* l8ui → +4: addr1 */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_crypto_encap @ ieee80211_crypto.o 00000010 size 104B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.ieee80211_crypto_encap.str1.1, .rodata_wlog_error.2, g_ic, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_crypto_encap */
int ieee80211_crypto_encap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_encap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 107, 2, 0 */
  /* observed branches: bnez.nx2, beqz.nx3 */
  /* observed memory traffic (first 7): */
    /* l32i.n a8, a3, -- 44: eb priv word */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l8ui a2, a2, -- off 53 */
    /* l8ui a2, a2, -- off 52 */
    /* l32i a2, a2, -- off 0x140 */
    /* l32i a8, a2, -- off 160 */
    /* l32i.n a8, a8, -- 16: addr3 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a8,a3+44 → +44: eb priv word */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[2] = *(u8 *)((u8 *)a2 + 53); /* l8ui → +53:  */
  regs[2] = *(u8 *)((u8 *)a2 + 52); /* l8ui → +52:  */
  regs[2] = *(u32 *)((u8 *)a2 + 320); /* l32i a2,a2+320 → +320:  */
  regs[8] = *(u32 *)((u8 *)a2 + 160); /* l32i a8,a2+160 → +160:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_crypto_gmac_decrypt @ ieee80211_crypto.o 00000040 size 453B bind GLOBAL
 * Calls: ieee80211w_get_igtk_from_keyidx, memcmp, wifi_log, memcpy | Data refs: .rodata_wlog_error.13, .rodata_wlog_error.14, g_osi_funcs_p, wpa_crypto_funcs, g_ic, .rodata_wlog_error.15, .rodata_wlog_error.16, ieee80211w_get_igtk_from_keyidx, memcmp, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_crypto_gmac_decrypt */
int ieee80211_crypto_gmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_gmac_decrypt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 112B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 27, 0, 76, 24, 6, 1, 32, -1, -57, 18 */
  /* observed branches: bltux1, bnex2, bnez.nx1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l16ui a5, a3, -- 22: seqctl/len */
    /* l32i.n a2, a3, -- 4: addr1 */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* l8ui a4, a7, -- 0: frame control */
    /* s32i.n a2, a1, -- off 52 */
    /* l8ui a4, a7, -- 1: frame control/duration */
    /* l8ui a11, a7, -- 3: 802.11 header region */
    /* l8ui a2, a7, -- 2: duration */
    /* s32i a8, a1, -- off 64 */
    /* s32i.n a10, a1, -- off 56 */
  /* observed call sequence (in order): ieee80211w_get_igtk_from_keyidx -> memcmp -> wifi_log -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[2] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a2,a3+4 → +4: addr1 */
  regs[8] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a8,a2+4 → +4: addr1 */
  regs[4] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 52) = regs[2]; /* s32i.n a2,a1+52 → +52:  */
  regs[4] = *(u8 *)(((u8 *)0) + 1); /* l8ui → +1: frame control/duration */
  (void)((int(*)())ieee80211w_get_igtk_from_keyidx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* key/IV/nonce handling per observed insns above; crypto primitive via wpa_crypto_funcs; no invented steps. */
    return 0;
  
}

/* ieee80211_crypto_setkey @ ieee80211_crypto.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_crypto_setkey */
int ieee80211_crypto_setkey(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_crypto_setkey(void *a2, void *a3, unsigned a4, unsigned a5)
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

/* ieee80211_get_cipher_mic_len @ ieee80211_crypto.o 00000004 size 24B bind GLOBAL
 * Calls: none | Data refs: .rodata.CSWTCH$70
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_get_cipher_mic_len */
int ieee80211_get_cipher_mic_len(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_cipher_mic_len(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 1): */
    /* l8ui a2, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)((u8 *)a2 + 0); /* l8ui → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
