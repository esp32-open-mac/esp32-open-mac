/* Reconstructed C for libwapi.a : wapi_glue.o (Xtensa ELF32 relocatable).
 * Source disasm: re/esp32/disasm_full/libwapi/wapi_glue.dis
 * Outgoing call args in a10/a11/a12/a13/a14/a15; wifi_log call shape is
 * wifi_log(1, 4, <1|2>, fmt, ...) with the numeric args observed per site.
 * Selector constants below (0x147200 etc.) are the literal-pool words at
 * .text.wapi_sm_parse_wapi_ie-0x50 +0x10/+0x14/+0x18 and the l32r-loaded
 * words in wapi_selector_to_bitfield / set_assoc_default.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;

extern void *g_osi_funcs_p; /* slots used: 0x144 (random), 0x16c (alloc/free), 176, 0xb0 */
extern void *memset(void *d, int v, unsigned n);
extern void *memcpy(void *d, const void *s, unsigned n);
extern int wifi_log(int a, int b, int c, const char *fmt, ...);
extern int esp_wifi_auth_done_internal(void);

/* WAPI state-machine block. Only offsets with 2+ observed accesses are
 * named; all other fields are accessed via byte offsets with comments.
 * Offset evidence (this object + wapi.o):
 *  +8:  u32 (set_param id 0 / get_param id 0; parse writes +4/+8 words)
 *  +0x174/+0x178/+0x17c: u32 key-mgmt selectors (set/get_param ids 1/2/3,
 *         parse stores, supplicant reads, check_header reads 0x17c)
 *  +0x128/+0x12c: u32 AP-IE len pair (set_ap_wapi_ie clears/sets)
 *  +0x120/+0x124: u32 assoc-IE len pair (set_assoc_default sets) */
typedef struct {
    u8  pad0[8];
    u32 f08;          /* offset 8 */
    u8  pad1[0x174 - 12];
    u32 f174;         /* offset 0x174 */
    u32 f178;         /* offset 0x178 */
    u32 f17c;         /* offset 0x17c */
} wapi_sm_t;

/* wapi_put_be32 @ wapi_glue.o section .text.wapi_put_be32 size 38B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - exact byte stores and cursor bump observed */
static u8 *wapi_put_be32(u8 **pp /*a2: pointer to cursor*/, u8 lo /*a3*/)
{
    u8 *p = *pp; /* l32i.n a8,a2,0 */
    p[0] = 0;    /* s8i 0 */
    p[1] = 20;   /* movi.n 20 */
    p[2] = 114;  /* movi 114 */
    p[3] = lo;   /* s8i a3 */
    p += 4;      /* addi.n 4 */
    *pp = p;     /* s32i.n */
    return p;
}

/* wapi_selector_to_bitfield @ wapi_glue.o section .text.wapi_selector_to_bitfield size 64B bind LOCAL
 * Calls: none | Data refs: literal words 0x00147200 and 0xffeb8dff
 * Fidelity: high - big-endian 4B load, two-constant compare, 1<<10 return observed */
static u32 wapi_selector_to_bitfield(const u8 *sel /*a2*/)
{
    /* u32 v = sel[0]<<24 | sel[1]<<16 | sel[2]<<8 | sel[3]
     * (note: byte 3 OR-ed without shift, byte 2 shifted 8 - observed order). */
    u32 v = ((u32)sel[0] << 24) | ((u32)sel[1] << 16) |
            ((u32)sel[2] << 8) | ((u32)sel[3]);
    u32 r = 1; /* movi.n a2,1 */
    if (v != 0x00147200u) {
        /* a8 = v + 0xffeb8dff; movnez r,0,a8: r stays 1 only if sum == 0,
         * i.e. v == -0xffeb8dff (mod 2^32), the second OUI constant. */
        if ((v + 0xffeb8dffu) != 0u)
            r = 0;
    }
    return r << 10; /* slli 10: 0x400 on match, else 0 */
}

/* wapi_neg_complete @ wapi_glue.o 00000004 size 11B bind GLOBAL
 * Calls: esp_wifi_auth_done_internal | Data refs: none
 * Fidelity: high - single tail call; return register (a2) never modified so incoming arg passes through */
int wapi_neg_complete(u32 arg)
{
    esp_wifi_auth_done_internal();
    return (int)arg; /* observed: no mov to a2 after call */
}

/* wapi_sm_asue_challenge @ wapi_glue.o 0000000c size 40B bind GLOBAL
 * Calls: g_osi_funcs_p slot 0x144 (random fill), wifi_log | Data refs: g_osi_funcs_p, .rodata_wlog_error.18("WAPI: wapi_sm_asue_challenge failed to assign random value")
 * Fidelity: high - call shape and bgez success test observed; return register passes incoming a2 through */
int wapi_sm_asue_challenge(u8 *buf /*a2*/, u8 *lenp /*a3; mov to a11, passed as 2nd arg*/)
{
    /* r = ((int(*)(u8*,u8*))tbl[0x144/4])(buf, lenp);
     * (l32i table[0], l32i +0x144, outgoing a10=buf, a11=lenp). */
    int r = ((int (*)(u8 *, u8 *))(*(u32 **)g_osi_funcs_p + 0x144u / 4u))(buf, lenp);
    if (r < 0) /* bgez a10 -> return */
        wifi_log(1, 4, 1, "WAPI: wapi_sm_asue_challenge failed to assign random value");
    return (int)buf; /* a2 never rewritten: returns incoming first arg (observed) */
}

/* wapi_sm_check_header @ wapi_glue.o 0000001c size 174B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.19("WAPI: Wrong Length"), .20("WAPI: Wrong WAPI Version"), .21("WAPI: Wrong WAPI Type"), .22("WAPI: Wrong packet subtype"), .23("WAPI: Wrong packet length"), .24("WAPI: Wrong receive packet sequence")
 * Fidelity: medium - all six checks, byte offsets, and expected constants recovered; exact (a2,a4,a5) roles inferred from use (sm, seq-base, total-len) */
int wapi_sm_check_header(wapi_sm_t *sm /*a2*/, const u8 *h /*a3*/,
                         u32 unused /*a4*/, u32 len /*a5, masked to 16 bits*/)
{
    u32 l = len & 0xffffu; /* extui a5,0,16 */
    /* Check 1: length. if (!(11 < l)) fail("Wrong Length").
     * (movi a8,11; bltu a8,a5 else fail). So minimum total length 12. */
    if (!(11u < l))
        goto fail_len;
    /* Check 2: version u16. v = be16(h[0..1]) byte-swapped form in disasm
     * (l8ui b1<<8|b0, swap halves, extui 16); require v == 1
     * else fail("Wrong WAPI Version"). */
    {
        u32 v = (u32)((h[0] << 8) | h[1]); /* big-endian view of same bytes */
        if (v != 1u)
            goto fail_version;
    }
    /* Check 3: type byte h[2] must be 1 else fail("Wrong WAPI Type"). */
    if (h[2] != 1u)
        goto fail_type;
    /* Check 4: subtype/flags vs sm->f17c<<12 and h[3] range:
     * a10 = sm->f17c (l32i +0x17c); a8 = 1<<12 scaled compare (slli 12);
     * if (sm->f17c != (1<<12)) require h[3] < 8 else require h[3] < 3
     * (bgeui 8 / bgeui 3), else fail("Wrong packet subtype"). */
    if (sm->f17c != (1u << 12)) {
        if (!(h[3] < 8u))
            goto fail_subtype;
    } else {
        if (!(h[3] < 3u))
            goto fail_subtype;
    }
    /* Check 5: length field be16(h[6..7]) must equal l
     * else fail("Wrong packet length"). */
    {
        u32 lf = (u32)((h[6] << 8) | h[7]);
        if (lf != l)
            goto fail_plen;
    }
    /* Check 6: sequence be16(h[8..9]) must be >= *(u16*)(sm + 0x170)
     * (l16ui +0x170); on success return 0, else fail("Wrong receive ..."). */
    {
        u32 sq = (u32)((h[8] << 8) | h[9]);
        u32 base = *(u16 *)((u8 *)sm + 0x170);
        if (sq >= base)
            return 0; /* movi.n a2,0; bgeu -> +0xac return */
    }
    wifi_log(1, 4, 1, "WAPI: Wrong receive packet sequence");
    return -1;

fail_len:     wifi_log(1, 4, 1, "WAPI: Wrong Length"); return -1;
fail_version: wifi_log(1, 4, 1, "WAPI: Wrong WAPI Version"); return -1;
fail_type:    wifi_log(1, 4, 1, "WAPI: Wrong WAPI Type"); return -1;
fail_subtype: wifi_log(1, 4, 1, "WAPI: Wrong packet subtype"); return -1;
fail_plen:    wifi_log(1, 4, 1, "WAPI: Wrong packet length"); return -1;
}

/* wapi_sm_get_param @ wapi_glue.o 00000000 size 53B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - full id switch with exact offsets observed */
u32 wapi_sm_get_param(wapi_sm_t *sm /*a2*/, u32 id /*a3*/)
{
    if (sm == 0)
        return 0; /* beqz -> return incoming a8=a2=NULL; observed mov a8,a2 */
    switch (id) {
    case 0: return sm->f08;   /* l32i.n +8 */
    case 1: return *(u32 *)((u8 *)sm + 0x174); /* l32i +0x174 */
    case 2: return *(u32 *)((u8 *)sm + 0x178); /* l32i +0x178 */
    case 3: return *(u32 *)((u8 *)sm + 0x17c); /* l32i +0x17c */
    default: return 0; /* movi.n a8,0 path */
    }
}

/* wapi_sm_set_param @ wapi_glue.o 00000000 size 67B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - full id switch with exact offsets; NULL sm returns -1, else 0 */
int wapi_sm_set_param(wapi_sm_t *sm /*a2*/, u32 id /*a3*/, u32 val /*a4*/)
{
    if (sm == 0)
        return -1; /* movi.n a8,-1; beqz -> return */
    switch (id) {
    case 0: sm->f08 = val; break;                          /* s32i.n +8 */
    case 1: *(u32 *)((u8 *)sm + 0x174) = val; break;        /* s32i +0x174 */
    case 2: *(u32 *)((u8 *)sm + 0x178) = val; break;        /* s32i +0x178 */
    case 3: *(u32 *)((u8 *)sm + 0x17c) = val; break;        /* s32i +0x17c */
    default: break; /* falls to return 0 (observed j +0x39) */
    }
    return 0; /* movi a8,0 */
}

/* wapi_sm_parse_wapi_ie @ wapi_glue.o 00000050 size 550B bind GLOBAL
 * Calls: memset, wifi_log, wapi_selector_to_bitfield | Data refs: .rodata.__func__("wapi_sm_parse_wapi_ie"), .rodata_wlog_error.2("... ie len too short %lu"), .3("... malformed ie or unknown version, id=%02u, len=%02u"), .4("... ie count both (key mgmt), count %u left %u"), .5("... ie too short (for capabilities)"), .6("... ie count botch (pairwise), count %u left %u"), .7("... ie too short (for key mgmt)"), .8("... ie length mismatch, %u too much"), .9("... ie has %u trailing bytes - ignored"), selector words 0x00147201/0x00147202/0xffeb8e00
 * Fidelity: low - 550B IE parser; phased pseudocode below follows observed branches/loops but selector-table semantics and some count-field roles are inferred, not proven */
int wapi_sm_parse_wapi_ie(const u8 *ie /*a2*/, u32 ie_len /*a3*/, wapi_sm_t *out /*a4*/)
{
    /* Phase 0: init out block.
     * memset(out+16, 0, 12) (a10=a4+16, a11=0, a12=12);
     * out[4B]=0x400; out[8B]=0x400; out[0B]=4; out[12B]=0x1000 (1<<12). */
    memset((u8 *)out + 16, 0, 12u);
    *(u32 *)((u8 *)out + 4) = 0x400u;
    *(u32 *)((u8 *)out + 8) = 0x400u;
    *(u32 *)((u8 *)out + 0) = 4u;
    *(u32 *)((u8 *)out + 12) = 0x1000u;
    /* Phase 1: length checks. ie_len==0 -> return 0.
     * ie_len<4 -> wifi_log(__func__, "ie len too short %lu", ie_len), return -1. */
    if (ie_len == 0)
        return 0;
    if (ie_len < 4u) {
        wifi_log(1, 4, 1, "%s: ie len too short %lu", "wapi_sm_parse_wapi_ie", ie_len);
        return -1;
    }
    /* Phase 2: header. Require ie[0]==68 ('D'/element id observed movi 68);
     * require ie[1]==ie_len-2; version = ie[3]<<8|ie[2] must be 1;
     * else log "malformed ie or unknown version, id=%02u, len=%02u" (id=ie[0]) and return -1. */
    if (ie[0] != 68u || ie[1] != (u8)(ie_len - 2u) ||
        (((u32)ie[3] << 8) | ie[2]) != 1u) {
        wifi_log(1, 4, 1, "%s: malformed ie or unknown version, id=%02u, len=%02u",
                 "wapi_sm_parse_wapi_ie", ie[0], ie_len);
        return -1;
    }
    /* Phase 3: AKM-suite list (offset 4..). count = ie[5]<<8|ie[4];
     * if count==0 require remaining==expected else "ie count both (key mgmt)"
     * style failure (rodata .4); each 4B selector folded via
     * wapi_selector_to_bitfield and OR-ed into out[12B] with (val<<4)
     * accumulation (slli a7,..,4 observed). Loop count times. */
    /* Phase 4: pairwise-cipher list. Same shape; failures log
     * "ie too short (for key mgmt)" (.7) / "ie count botch (pairwise)" (.6);
     * selector bits via wapi_selector_to_bitfield OR-ed into out[4B]. */
    /* Phase 5: group-cipher selector (single 4B): bitfield via
     * wapi_selector_to_bitfield stored to out[8B]; length underflow logs
     * "ie too short (for capabilities)" (.5). */
    /* Phase 6: capabilities u16 at cursor stored to out[16B] (s32i +16);
     * leftover>1 logs "ie length mismatch, %u too much" (.8), leftover==1
     * logs "ie has %u trailing bytes - ignored" (.9); both still return 0.
     * Any hard failure returns -1 with a6=-1 (observed movi -1 paths). */
    {
        u32 cursor = 6u; /* first count field offset observed (l8ui +4/+5) */
        u32 left = ie_len - 4u;
        (void)cursor; (void)left;
        /* Full per-element decode omitted: see disasm labels +0xcd..+0x270
         * for the exact count Baijiu: (count<<2)+6 bound checks, addx4
         * pointer math, and bitfield-or accumulation. */
    }
    return 0;
}

/* wapi_sm_set_ap_wapi_ie @ wapi_glue.o 00000010 size 118B bind GLOBAL
 * Calls: g_osi_funcs_p slots 176/0x16c (free/alloc), wifi_log, memcpy | Data refs: g_osi_funcs_p, .rodata_wlog_warning.17("WAPI: clearing AP RSN IE.")
 * Fidelity: medium - NULL guard, free/alloc call shapes and clear-path stores observed; exact (a3,a4) IE/len roles inferred from use */
int wapi_sm_set_ap_wapi_ie(wapi_sm_t *sm /*a2*/, const u8 *ie /*a3*/, u32 len /*a4*/)
{
    u32 old;
    if (sm == 0)
        return -1; /* bnez guard; movi -1 */
    /* old = *(sm+0x128); ((void(*)(u32))tbl[176/4])(old) -> frees old IE.
     * (l32i table[0], l32i +176, outgoing a10=old). */
    old = *(u32 *)((u8 *)sm + 0x128);
    ((void (*)(u32))(*(u32 **)g_osi_funcs_p + 176u / 4u))(old);
    /* a9 = (ie == NULL); if set -> clear path: log + zero lens, return 0. */
    if (ie == 0) {
        wifi_log(1, 4, 2, "WAPI: clearing AP RSN IE.");
        *(u32 *)((u8 *)sm + 0x128) = 0;
        *(u32 *)((u8 *)sm + 0x12c) = 0;
        return 0;
    }
    /* new = ((void*(*)(u32))tbl[0x16c/4])(len); outgoing a10=len(a4).
     * stored to sm+0x128; if NULL return ... (beqz a10 -> return incoming -1
     * path at +0x5: observed branch back to entry-prologue return slot). */
    {
        void *nw = ((void *(*)(u32))(*(u32 **)g_osi_funcs_p + 0x16cu / 4u))(len);
        *(u32 *)((u8 *)sm + 0x128) = (u32)nw;
        if (nw == 0)
            return -1;
        /* memcpy(nw, ie, len) (outgoing a10=nw?/a11=ie/a12=len per pattern),
         * then *(sm+0x12c) = len; return incoming a5 (observed mov a2,a5:
         * second-arg passthrough, value 1 on this path). */
        memcpy(nw, ie, len);
        *(u32 *)((u8 *)sm + 0x12c) = len;
        return 1;
    }
}

/* wapi_sm_set_assoc_wapi_ie_default @ wapi_glue.o 00000040 size 364B bind GLOBAL
 * Calls: wapi_put_be32, wifi_log, memcpy, g_osi_funcs_p slot 0x16c (alloc) | Data refs: selector words 0x00147201/0x00147202, .rodata_wlog_error.11("Invalid AKM mode (%d)."), .12("Invalid pairwise cipher (%d)."), .13("Invalid group cipher (%d)."), .14/.16("%s %d" with "wapi_glue.c",237/0x179), g_osi_funcs_p
 * Fidelity: low - 364B IE builder; phases below follow observed stores/calls but pairwise/group selection and length-cap (23) handling are structural */
int wapi_sm_set_assoc_wapi_ie_default(wapi_sm_t *sm /*a2*/, u8 *out /*a3*/,
                                      u32 *lenp /*a4*/)
{
    u32 cap;
    if (sm == 0)
        return -1; /* bnez guard */
    cap = *lenp; /* l32i.n a4,0 */
    *(u32 *)((u8 *)out - 16 + 32) = cap; /* s32i to a1+16 spill slot (observed) */
    if (cap < 23u) /* bgeu 23,cap -> fail path returning -1 */
        return -1;
    /* Header bytes: out[0]=68, out[1]=0, out[5]=0, cursor=out+6;
     * out[3]=0, out[2]=1, out[4]=1 (s8i sequence observed);
     * capability bits from sm->f17c: if == 1<<13 use selector 0x147201
     * else if == 1<<12 use 0x147202 else log "Invalid AKM mode" and fail. */
    out[0] = 68; out[1] = 0; out[5] = 0;
    out[3] = 0; out[2] = 1; out[4] = 1;
    {
        u32 akm = *(u32 *)((u8 *)sm + 0x17c);
        u32 pairwise = *(u32 *)((u8 *)sm + 0x178);
        u32 group = *(u32 *)((u8 *)sm + 0x174);
        u8 *cur = out + 6;
        (void)pairwise; (void)group;
        if (akm != (1u << 13) && akm != (1u << 12)) {
            wifi_log(1, 4, 4, "Invalid AKM mode (%d).", akm);
            return -1;
        }
        /* wapi_put_be32(&cur, selector-lo-byte) for AKM selector;
         * then pairwise section: if pairwise==0x400 emit single default
         * selector else validate/emit, mismatch logs "Invalid pairwise
         * cipher (%d)." / "Invalid group cipher (%d)." with %s %d
         * ("wapi_glue.c", 237 / 0x179) diagnostics observed. */
        wapi_put_be32(&cur, (u8)akm);
        /* Length fixups: out[1] = cur-out-2 (addi -2, s8i +1 observed);
         * capacity check vs cap (bgeu -> fail); Assoc-IE bookkeeping:
         * if (*(sm+0x120)==0) alloc via tbl[0x16c] and memcpy cur image,
         * set sm+0x124/0x120 lens; return 0, else -1 paths as observed. */
        out[1] = (u8)((u32)(cur - out) - 2u);
        *lenp = (u32)(cur - out);
        *(u32 *)((u8 *)sm + 0x124) = *lenp;
        return 0;
    }
}

/* wapi_sm_set_header @ wapi_glue.o 00000000 size 58B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - all 12 byte stores and +12 return observed */
u8 *wapi_sm_set_header(u8 *p /*a2*/, u32 f1 /*a3: low byte -> +9, high byte -> +8*/, u32 f2 /*a4 -> +3*/)
{
    p[0] = 0;                /* s8i 0 */
    p[6] = 0; p[7] = 0;      /* s8i 0 */
    p[1] = 1; p[2] = 1;      /* s8i 1 */
    p[3] = (u8)f2;           /* s8i a4 */
    p[4] = 0; p[5] = 0;      /* s8i 0 */
    p[8] = (u8)(f1 >> 8);    /* extui a3,8,8 */
    p[9] = (u8)f1;           /* s8i a3 */
    p[10] = 0; p[11] = 0;    /* s8i 0 */
    return p + 12;           /* addi.n +12 */
}

/* wapi_supplicant_key_neg_complete @ wapi_glue.o 00000018 size 116B bind GLOBAL
 * Calls: wifi_log, esp_wifi_auth_done_internal | Data refs: .rodata triple "NONE\0SMS4\0UNKNOWN\0" (+0/+5/+10), .rodata_wlog_info.15("WAPI negotiation completion with %02x:%02x:%02x:%02x:%02x:%02x [PTK=%s GTK=%s]")
 * Fidelity: medium - MAC bytes, PTK/GTK string selection (1->offset5 "SMS4"?/0x400->offset0 "NONE" else +10 "UNKNOWN"), log arg packing and state stores observed; exact string-index polarity inferred from beq order */
int wapi_supplicant_key_neg_complete(wapi_sm_t *sm /*a2*/, const u8 *mac /*a3: 6 bytes l8ui +0..+5*/)
{
    u32 ptk = *(u32 *)((u8 *)sm + 0x174); /* l32i +0x174 */
    u32 gtk = *(u32 *)((u8 *)sm + 0x178); /* l32i +0x178 */
    const char *ps, *gs;
    /* Selection observed: if val==1 use base+5 else if val!=0x400 use base+10
     * else base+0. Base triple: "NONE"(+0) "SMS4"(+5) "UNKNOWN"(+10). */
    ps = (ptk == 1u) ? "SMS4" : (ptk != 0x400u ? "UNKNOWN" : "NONE");
    gs = (gtk == 1u) ? "SMS4" : (gtk != 0x400u ? "UNKNOWN" : "NONE");
    /* wifi_log(1,4,3?, fmt-info15, mac[0..5], ps, gs) with stack-packed args
     * (s32i/s8i to a1+0..+20 observed), then *(sm+4)=0 (s32i 0,+4),
     * esp_wifi_auth_done_internal(), *(sm+0x170)=0, return. */
    wifi_log(1, 4, 3, "WAPI negotiation completion with %02x:%02x:%02x:%02x:%02x:%02x [PTK=%s GTK=%s]",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ps, gs);
    *(u32 *)((u8 *)sm + 4) = 0;
    esp_wifi_auth_done_internal();
    *(u32 *)((u8 *)sm + 0x170) = 0;
    return 0;
}
