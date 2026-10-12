/* Reconstructed C for libwapi.a : wapi_sms4_algo.o (Xtensa ELF32 relocatable).
 * Source disasm: re/esp32/disasm_full/libwapi/wapi_sms4_algo.dis
 * Outgoing call args in a10/a11/a12/...; static helpers live in their own
 * .text sections; first 0x10/0x20 bytes of sms4 sections are literal pools
 * (entries at +0x0: 0xff00ff00 mask words, Sbox/CK relocs), so real code
 * entry is at section+0x10 (sms4_crypt) / +0x20 (key_expansion). Call targets
 * observed as `sms4_crypt+0x10`, `sms4_key_expansion+0x20` via ASM_EXPAND.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;

extern void *memcpy(void *d, const void *s, unsigned n);

/* Tables (file offsets in .o; runtime addresses assigned at link) */
extern u8  Sbox[256];  /* .rodata.Sbox, 256B */
extern u32 CK[32];     /* .rodata.CK, 128B */
extern u32 FK[4];      /* .rodata.FK, 16B: a3b1bac6 56aa3350 677d9197 b27022dc */

/* sms4_crypt @ wapi_sms4_algo.o section .text.sms4_crypt+0x10 size 655B bind LOCAL
 * Calls: none | Data refs: Sbox, mask words 0x00ff00ff/0xff00ff00 (literal pool)
 * Fidelity: medium - 8x hardware-loop (loop a5=8) of 4-round groups (=32 SMS4 rounds) recovered; Sbox lookups and byte-swap src/ssai prologue+epilogue observed, rotation amounts (ssai 8/14/22/30/16) noted but round-function wiring below is structural, not a verified re-implementation */
static void sms4_crypt(const u32 *in_w /*a2: 4 input words*/,
                       u32 *out_w /*a3: 4 output words*/,
                       const u32 *rk /*a4: round keys, +16 per group*/)
{
    /* Prologue (observed): each input word byte-swapped via ssai 16 + src,
     * then split with masks 0x00ff00ff/0xff00ff00 into (a10,a8),(a9,a2),
     * (a12,a5),(a9?,a2) pairs. Four working words held in (a8,a15,a14,a10)
     * rotation slots. */
    u32 x0, x1, x2, x3; /* working state, rotated each round group */
    const u8 *sb = Sbox;
    int grp;

    x0 = in_w[0]; x1 = in_w[1]; x2 = in_w[2]; x3 = in_w[3]; /* + byte-swap each */
    for (grp = 0; grp < 8; grp++) { /* movi a5,8; hardware loop */
        /* Each group consumes 4 round keys (l32i a4+0/+4/+8/+12, a4 += 16)
         * and performs 4 SMS4 rounds of the form:
         *   t = x1 ^ x2 ^ x3 ^ rk[i];
         *   t = Sbox(t.b3)<<24 ^ Sbox(t.b0) ^ Sbox(t.b2)<<16 ^ Sbox(t.b1)<<8;
         *   t = L(t) via src with ssai 22/30 (then 14/8) xor-chain;
         *   (x0,x1,x2,x3) = (x1,x2,x3,x0 ^ t-variant per slot).
         * Sbox indexed as sb[byte + (u32)Sbox-base] (add.n a6,a9,a6; l8ui).
         * State words rotate slots between groups (a8/a15/a14/a10). */
        (void)sb; (void)rk;
        rk += 4;
    }
    /* Epilogue (observed): reverse byte-swap (ssai 16 + src) of the four
     * state words, mask/merge with 0x00ff00ff/0xff00ff00, store to out[0..3],
     * memw, return. Output order is the reversed state (standard SMS4
     * reverse-final: out = (x3,x2,x1,x0) post swap). */
    out_w[0] = x0; out_w[1] = x1; out_w[2] = x2; out_w[3] = x3;
}

/* sms4_key_expansion @ wapi_sms4_algo.o section .text.sms4_key_expansion+0x20 size 549B bind LOCAL
 * Calls: none | Data refs: Sbox, CK, FK words (a3b1bac6 56aa3350 677d9197 b27022dc), masks 0x00ff00ff/0xff00ff00
 * Fidelity: medium - key-xor-FK init, 8x loop producing 32 round keys, and encrypt/decrypt reversal tail all observed; L' mixing (ssai 19/9) structural */
static void sms4_key_expansion(const u32 *key /*a2: 4 key words*/,
                               u32 *rk_out /*a3/a14: 32-word round-key buffer*/,
                               u32 enc_flag /*a4: 1 = keep order (encrypt), else reverse*/)
{
    /* Init (observed): byte-swap each key word; k[i] ^= FK[i] with FK words
     * a3b1bac6, 56aa3350, 677d9197, b27022dc (literals +0x8..+0x14). */
    u32 k0 = key[0] /*swapped*/ ^ 0xa3b1bac6u;
    u32 k1 = key[1] /*swapped*/ ^ 0x56aa3350u;
    u32 k2 = key[2] /*swapped*/ ^ 0x677d9197u;
    u32 k3 = key[3] /*swapped*/ ^ 0xb27022dcu;
    const u32 *ck = CK; /* l32i a15+0/+4/+8/+12, a15 += 16 per group */
    int grp;

    for (grp = 0; grp < 8; grp++) { /* countdown a5 from 8, bnez */
        /* 4 subkeys per group: t = k1^k2^k3^CK[i]; Sbox-substitute each byte;
         * L'(t): src ssai 19 then ssai 9 xor-chain (observed ssai 9/19);
         * rk[4*grp+j] = k0 ^ L'(t) etc. with state rotation. */
        (void)ck;
        rk_out[4 * grp + 0] = k0; /* s32i to a14+0/+4/+8/+12 */
        rk_out[4 * grp + 1] = k1;
        rk_out[4 * grp + 2] = k2;
        rk_out[4 * grp + 3] = k3;
        ck += 4;
    }
    /* Tail (observed): if (enc_flag != 1): reverse-copy 32 words
     * (a3 += 124; 16x l32i/s32i pairs stepping -4/+4). Else keep order. */
    if (enc_flag != 1u) {
        int i;
        for (i = 0; i < 16; i++) { /* movi a4,16 countdown */
            u32 t = rk_out[i];
            rk_out[i] = rk_out[31 - i];
            rk_out[31 - i] = t;
        }
    }
    (void)k0; (void)k1; (void)k2; (void)k3;
}

/* wapi_sm_wpi_crypt$part$0 @ wapi_sms4_algo.o section .text.wapi_sm_wpi_crypt$part$0+0xc size 180B bind LOCAL
 * Calls: sms4_key_expansion, sms4_crypt | Data refs: none
 * Fidelity: medium - frame (entry a1,192), key schedule, 16B-block loop with end-marker word at frame+144, and <16B remainder byte-xor loop all observed */
static int wpi_crypt_part0(u32 a2_ret /*saved*/, u8 *in /*a3*/,
                           u32 len /*a4*/, const u8 *key /*a5*/,
                           u8 *out /*a6*/, u32 mode /*a7/a12 in, a15: 0=enc 1=dec*/)
{
    u8 frame[176];   /* entry a1,192 stack frame; key schedule inside */
    u32 *rk = (u32 *)frame;
    u32 full = (len >> 4) << 4;  /* extui a4,0,4 then slli 4: len & ~15 */
    u32 rem = len & 15u;         /* extui a5,a4,0,4 */
    u8 *p_in = in, *p_out = out;
    u32 n;

    /* sms4_key_expansion(key, rk, mode): outgoing a10=a5(key), a11=frame,
     * a12=a7(mode). Observed call to sms4_key_expansion+0x20. */
    sms4_key_expansion((const u32 *)key, rk, mode);

    /* First block pre-pass (observed): sms4_crypt(in, frame+128-window, rk)
     * with a10=data, a11=key-schedule area, a12=frame; exact buffer roles
     * for the first call vs loop calls differ (pre-pass uses a11=a1+128
     * region); modelled here as crypt into chaining buffer. */
    /* Block loop over `full` bytes, 16B at a time:
     * each iteration xors 4 input words with chaining words at frame+128..
     * calls sms4_crypt, stores end pointer at frame+144 (s32i a8,a1,144),
     * loops while (p_in != *(frame+144)) (bne a3,a8). */
    for (n = 0; n < full; n += 16u) {
        /* out_w[i] = in_w[i] ^ chain[i]; crypt; chain = out (CBC-like);
         * exact chaining direction (enc vs dec) follows mode. */
        sms4_crypt((const u32 *)p_in, (u32 *)p_out, rk);
        p_in += 16; p_out += 16;
    }
    /* Remainder loop (observed, `rem` iterations): out[i] = in[i] ^ pad[i]
     * bytewise (l8ui/s8i/xor/s8i with addi 1 countdown, bne a5,a3). */
    for (n = 0; n < rem; n++)
        p_out[n] = (u8)(p_in[n] ^ frame[128 + n]);
    (void)a2_ret;
    return 0; /* movi.n a2/a3,0; memw */
}

/* wapi_sm_wpi_encrypt @ wapi_sms4_algo.o 00000004 size 30B bind GLOBAL
 * Calls: wapi_sm_wpi_crypt$part$0 | Data refs: none
 * Fidelity: high - argument shuffle (a10..a14 = a2..a6), len==0 early-out returning 1, else tail call with mode 0 */
int wapi_sm_wpi_encrypt(void *p0, u8 *in, u32 len, const u8 *key, u8 *out,
                        u32 mode_hi)
{
    if (len == 0)
        return 1; /* movi.n a2,1; beqz a4 -> return */
    /* part0(p0, in, len, key, out, 0): outgoing a15 = 0 (movi a15,0). */
    wpi_crypt_part0((u32)p0, in, len, key, out, 0u);
    (void)mode_hi;
    return 0; /* call return arrives in a10, moved to a2 */
}

/* wapi_sm_wpi_decrypt @ wapi_sms4_algo.o 00000004 size 30B bind GLOBAL
 * Calls: wapi_sm_wpi_crypt$part$0 | Data refs: none
 * Fidelity: high - same shuffle as encrypt but mode 1; len==0 path returns incoming p0 (asymmetric with encrypt, as observed) */
int wapi_sm_wpi_decrypt(void *p0, u8 *in, u32 len, const u8 *key, u8 *out,
                        u32 mode_hi)
{
    if (len == 0)
        return (int)p0; /* mov a15,a10(saved a2); mov a2,a15 */
    /* part0(p0, in, len, key, out, 1): outgoing a15 = 1 (movi a15,1). */
    wpi_crypt_part0((u32)p0, in, len, key, out, 1u);
    (void)mode_hi;
    return 0;
}

/* wapi_sm_wpi_calc_mic @ wapi_sms4_algo.o 00000014 size 196B bind GLOBAL
 * Calls: sms4_key_expansion, sms4_crypt, memcpy | Data refs: none
 * Fidelity: medium - len==0 early-out (return 1), key schedule, full-block CBC-MAC-style loop with end-marker compare, remainder byte-xor + memcpy tail and final crypt all observed; chaining direction structural */
int wapi_sm_wpi_calc_mic(u8 *iv /*a2->a7*/, u8 *data /*a3*/, u32 len /*a4*/,
                         const u8 *key /*a5*/, u8 *mic_out /*a6*/)
{
    u8 frame[160]; /* entry a1,176 */
    u32 *rk = (u32 *)frame;
    u32 full = (len >> 4) << 4;  /* srli/slli 4 pair */
    u32 rem = len & 15u;         /* extui 0,4 */
    u8 *p = data;
    u32 n;

    if (len == 0)
        return 1; /* movi.n a2,1; beqz a4 -> +0xc2 return */

    sms4_key_expansion((const u32 *)key, rk, 1u); /* a12/outgoing mode consts per disasm */
    /* First crypt pre-pass (observed call before loop), then loop while
     * (p_end != p): 4-word xor with chaining block at frame+128..,
     * sms4_crypt, p += 16 (addi a3,16). */
    for (n = 0; n < full; n += 16u) {
        sms4_crypt((const u32 *)p, (u32 *)(frame + 128), rk);
        p += 16;
    }
    if (rem == 0)
        return 0; /* beq a5,a2(0) -> +0xc2 with a2=0 */
    /* Remainder: byte-xor `rem` input bytes with chaining tail
     * (l8ui/s8i/xor loop, countdown a4, bnez), then:
     * memcpy(frame+128+rem?, src, 16-rem) (a12 = 16-rem via sub),
     * final sms4_crypt, return 0. */
    for (n = 0; n < rem; n++)
        frame[128 + n] ^= p[n];
    memcpy(frame + 128 + rem, data /*tail src per register flow*/, (unsigned)(16u - rem));
    sms4_crypt((const u32 *)(frame + 128), (u32 *)mic_out, rk);
    (void)iv; (void)mic_out;
    return 0;
}
