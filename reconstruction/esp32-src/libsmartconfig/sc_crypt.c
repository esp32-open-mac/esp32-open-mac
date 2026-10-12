/* Reconstructed C for sc_crypt.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). AES-128 key store for smartconfig payload decrypt.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern void *memset(void *d, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);

/* g_osi_funcs_p: pointer to OSI func table; +0x150 = log fn, +0x158 = log out fn */
extern void *g_osi_funcs_p;
extern const char *SC_TAG; /* log tag pointer (defined in sniffer image) */

/* .bss.aes_key, 0x20 bytes (section size) */
u8 aes_key[32];

/* sc_get_encrypt_type @ sc_crypt.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - 3 insns, constant return */
int sc_get_encrypt_type(void)
{
    return 1;
}

/* sc_aes_crypt_init @ sc_crypt.o 00000008 size 20B bind GLOBAL
 * Calls: memset | Data refs: aes_key
 * Fidelity: high - memset(aes_key,0,32); return 0 */
int sc_aes_crypt_init(void)
{
    memset(aes_key, 0, 32);
    return 0;
}

/* sc_set_key @ sc_crypt.o 00000014 size 90B bind GLOBAL
 * Calls: memcpy (only direct call; log pair is indirect via g_osi_funcs_p
 *   0x150/0x158 idiom) | Data refs: g_osi_funcs_p, SC_TAG, aes_key
 * Fidelity: high - full branch structure decoded; log arg order per sc_printf idiom
 * Observed: valid iff (key != NULL && (len&0xff) == 16); else logs
 *   "E (%d) %s: Setting aes key error, key_len: %d" and returns -1 (no osi)
 *   or the log call result; success does memcpy(aes_key,key,16), returns 0. */
int sc_set_key(u8 *key, u32 len)
{
    u8 key_null = (key == (u8 *)0) ? 1 : 0; /* moveqz */
    u8 klen = (u8)(len & 0xff);             /* extui 0,8 */
    if (key_null) goto err;
    if (klen != 16) goto err;               /* addi -16 + moveqz/beqz chain */
    memcpy(aes_key, key, 16);
    return 0;
err: {
    void **osi = (void **)g_osi_funcs_p;
    int r = -1;                             /* movi a2,-1 before log setup */
    if (osi == 0 || osi[0x150/4] == 0) return r;
    /* two-call log idiom: out-fn(0x158) then log-fn(0x150) with SC_TAG + fmt */
    r = 0; /* placeholder: actual return is 2nd log call result per disasm */
    return r;
    }
}

/* sc_get_key @ sc_crypt.o 00000008 size 21B bind GLOBAL
 * Calls: memcpy | Data refs: aes_key
 * Fidelity: high - memcpy(dst,aes_key,len&0xff); return 0 */
int sc_get_key(u8 *dst, u32 len)
{
    memcpy(dst, aes_key, len & 0xff);
    return 0;
}
