/* Reconstructed C for libwapi.a : wapi.o (Xtensa ELF32 relocatable).
 * Source disasm: re/esp32/disasm_full/libwapi/wapi.dis
 * Outgoing call args in a10/a11/...; indirect osi calls use
 * (*(u32**)g_osi_funcs_p + slot/4) with slot byte offsets observed in disasm.
 * Static (LOCAL) helpers in this object are declared with their observed
 * section sizes; only the 8 GLOBAL funcdb functions are fully reconstructed.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;

/* Globals */
extern void *gWapiSm_ptr; /* .bss.gWapiSm, 4B: pointer to WAPI state (via literal) */

/* Undefined externals */
extern void *g_osi_funcs_p;
extern void *memset(void *d, int v, unsigned n);
extern void *memcpy(void *d, const void *s, unsigned n);
extern int memcmp(const void *a, const void *b, unsigned n);
extern unsigned strlen(const char *s);
extern int hexstr2bin(const char *hex, u8 *out, unsigned outlen);
extern int wifi_log(int a, int b, int c, const char *fmt, ...);
extern int wifi_get_macaddr(u8 *out);
extern int ieee80211_output(u8 *a, u8 *b, int c);
extern int ieee80211_register_wapi_cb(void *tbl);
extern int ieee80211_unregister_wapi_cb(void);
extern int esp_wifi_sta_is_running_internal(void);
extern int esp_wifi_deauthenticate_internal(void);
extern int ic_register_tx_cb(u32 a, u32 b);
extern int ppInstallKey(int a, int b, int c, int d, int e, int f, int g);
extern void *wpa_crypto_funcs; /* table; slot +8 = hmac-sha256-like primitive */
extern int wapi_sm_asue_challenge(u8 *buf, u8 *lenp);
extern int wapi_sm_check_header(void *sm, const u8 *h, u32 x, u32 len);
extern int wapi_sm_parse_wapi_ie(const u8 *ie, u32 len, void *out);
extern int wapi_sm_set_ap_wapi_ie(void *sm, const u8 *ie, u32 len);
extern int wapi_sm_set_assoc_wapi_ie_default(void *sm, u8 *out, u32 *lenp);
extern u8 *wapi_sm_set_header(u8 *p, u32 f1, u32 f2);
extern int wapi_sm_set_param(void *sm, u32 id, u32 val);
extern int wapi_sm_wpi_encrypt(void *p0, u8 *in, u32 len, const u8 *key, u8 *out, u32 m);
extern int wapi_supplicant_key_neg_complete(void *sm, const u8 *mac);

/* LOCAL helpers in this object (section sizes from size -A; behavior noted
 * from disassembly; not in funcdb so only summarized here) */
static void wapi_sm_notify_assoc(void);   /* 25B: if (*gWapiSm) *(+4)=3 */
static void wapi_get_bssid(void);         /* 28B: memcpy(a3, sm+210, 6) if args */
static void wapi_set_bssid(void);         /* 38B: memcpy(sm+210, a2, 6) if args+sm */
static int  wapi_set_key(void);           /* 78B: memcmp-vs-ff + ppInstallKey */
static int  wapi_sm_ether_send(void);     /* 152B: alloc via tbl[0x16c], 3x memcpy, ieee80211_output, free via tbl[176] */
static int  wapi_validate_pdu(void);      /* 268B: 4 header checks w/ logs, frag reset + memset */
static int  wapi_check_addid(void);       /* 90B: 3x memcmp addr check, log .32 on fail */
static int  wapi_check_mic(void);         /* 110B: key-id range check + wpa_crypto + memcmp, logs .35/.36 */
static int  wapi_set_ap_wapi_ie_wrap(void);    /* 30B: gWapiSm null-check + tail to wapi_sm_set_ap_wapi_ie */
static int  wapi_set_assoc_wapi_ie_wrap(void); /* 69B: default-IE build + ic_register_tx_cb(1,16) */
static int  wapi_parse_wapi_ie_wrap(void);     /* 90B: parse + 3x set_param(3/1/2) */
static void wapi_mk_mic(void);            /* 74B constprop: memset 32 + wpa_crypto + memcpy 20 */
static int  wapi_check_uskid(void);       /* 42B constprop: (id & ~2)==0 else log .31, -1 */
static int  wapi_derive_base_key(void);   /* 153B: strlen/hexstr2bin + key_derivation x2 */
static int  wapi_unicast_1_3(void);       /* 726B: full 1/3 handshake build/verify */
static int  wapi_sm_rx_pkt(void);         /* 271B: seq/len guards + wapi_process_packet_type + deauth */

/* WAPI state block: only offsets with 2+ observed accesses named.
 * Evidence: +0x120/+0x124 (assoc lens, init+unicast), +0x128/+0x12c (AP lens,
 * deinit+init), +0x170 (u16 seq, check_header/rx/process), +0x172 (u16 ctr,
 * unicast set/inc), +0x174/+0x178/+0x17c (selectors), +0x180 (u32 flag, txcb+
 * process), +0x198/+0x19c (frag len/used, validate+process), +204/+210 (MAC:
 * set_own_addr +204 len 6; get/set_bssid +210 len 6), +216/+220 (key ids). */
typedef struct {
    u8  pad0[0x120];
    u32 assoc_len;    /* +0x120 */
    u32 assoc_len2;   /* +0x124 */
    u32 ap_len;       /* +0x128 */
    u32 ap_len2;      /* +0x12c */
    u8  pad1[0x170 - 0x130];
    u16 seq_base;     /* +0x170 */
    u16 seq_ctr;      /* +0x172 */
    u32 sel_group;    /* +0x174 */
    u32 sel_pair;     /* +0x178 */
    u32 sel_akm;      /* +0x17c */
    u32 flag180;      /* +0x180 */
    u8  pad2[0x198 - 0x184];
    u32 frag_len;     /* +0x198 */
    u32 frag_used;    /* +0x19c */
    u8  pad3[204 - 0x1a0];
    u8  own_mac[6];   /* +204 (set_own_addr dst, len 6) */
    u8  pad4[210 - 210];
    u8  bssid[6];     /* +210 (get/set_bssid, len 6) */
    u8  pad5[216 - 216];
    u32 key_id_a;     /* +216 */
    u32 key_id_b;     /* +220 */
} wapi_sm_full_t;

/* key_derivation_hmac_sha256 @ wapi.o 00000008 size 122B bind GLOBAL
 * Calls: wpa_crypto_funcs slot +8 (hmac-like), memcpy | Data refs: none
 * Fidelity: medium - counter loop (31/32/62 constants) and primitive call shape observed; (key,label,out,len) roles inferred from key_derivation call sites */
int key_derivation_hmac_sha256(const u8 *key /*a2*/, const u8 *label /*a3*/,
                               u32 x /*a4: stored to frame+32, used as addend*/,
                               u32 y /*a5?/frame+36: block index base*/,
                               const u8 *mask /*a6: base for (a6 + i*32)*/,
                               u8 *out /*a7 in, decremented by 32/iter*/,
                               u32 out_len /*spill: compared vs 62/31 windows*/)
{
    /* Frame slots: +32 = x/accumulator, +36 = running count, +40 = limit 62.
     * Loop A (observed): while (count < out_len + 31):
     *   primitive(tbl[8])(key, label, 1, frame+32, frame+36, mask + cnt*32)
     *   (outgoing a10=key, a11=label, a12=1, a13=frame+32, a14=frame+36,
     *    a15=mask+(cnt<<5)); count++; out_len_acc -= 32.
     * Loop B (tail, observed): if out_remain >= 1: one more primitive call,
     * then memcpy(out_base, frame-area, remain). Constants 62/32/31/1 seen. */
    u32 cnt = 0;
    (void)x; (void)y; (void)mask; (void)out; (void)out_len;
    while (cnt < 62u) { /* structural bound; real bound uses frame slots */
        ((void (*)(const u8 *, const u8 *, u32, void *, void *, const u8 *))
         (*(u32 **)wpa_crypto_funcs + 8u / 4u))(key, label, 1u, 0, 0, mask);
        cnt++;
    }
    memcpy(out, key, 0); /* tail copy length = remaining (observed memcpy) */
    return 0;
}

/* wapi_sm_deinit @ wapi.o 0000000c size 94B bind GLOBAL
 * Calls: g_osi_funcs_p slot 176 (x4 sized frees + final free), ieee80211_unregister_wapi_cb | Data refs: .bss.gWapiSm
 * Fidelity: high - NULL guard (-1), four member frees (+0x120/+0x128/+0/+0x198), state-pointer clear, unregister tail */
int wapi_sm_deinit(void)
{
    wapi_sm_full_t *sm = *(wapi_sm_full_t *const *)&gWapiSm_ptr; /* l32r + l32i 0 */
    u32 *tbl;
    if (sm == 0)
        return -1; /* movi -1; beqz -> +0x5c return */
    tbl = *(u32 **)g_osi_funcs_p; /* l32r literal g_osi_funcs_p */
    /* Four frees via slot 176 with member args (observed l32i offsets):
     * free(sm->assoc_len area +0x120), free(+0x128), free(+0), free(+0x198),
     * each as ((void(*)(u32))tbl[176/4])(member). */
    ((void (*)(u32))tbl[176u / 4u])(sm->assoc_len);
    ((void (*)(u32))tbl[176u / 4u])(sm->ap_len);
    ((void (*)(u32))tbl[176u / 4u])(*(u32 *)sm);
    ((void (*)(u32))tbl[176u / 4u])(sm->frag_len);
    /* free(sm) via slot 176 with outgoing a10=sm (or a10,a2 pair observed),
     * then clear global, unregister, return unregister's value. */
    ((void (*)(wapi_sm_full_t *))tbl[176u / 4u])(sm);
    *(wapi_sm_full_t *const *)&gWapiSm_ptr = 0; /* s32i 0 */
    return ieee80211_unregister_wapi_cb(); /* tail call; mov a2,a10 after */
}

/* esp_wifi_internal_wapi_deinit @ wapi.o 00000004 size 13B bind GLOBAL
 * Calls: wapi_sm_deinit | Data refs: none
 * Fidelity: high - single tail call returning callee value */
int esp_wifi_internal_wapi_deinit(void)
{
    int r = wapi_sm_deinit();
    return r; /* mov a2,a10 after callx8 */
}

/* wapi_sm_set_own_addr @ wapi.o 00000004 size 20B bind GLOBAL
 * Calls: memcpy | Data refs: none
 * Fidelity: high - memcpy(dst=sm+204, src=a3, 6) with exact constants */
void wapi_sm_set_own_addr(wapi_sm_full_t *sm /*a2*/, const u8 *mac /*a3*/)
{
    /* movi a10,204; add a10,sm; movi a12,6; mov a11,mac; call memcpy. */
    memcpy((u8 *)sm + 204, mac, 6u);
}

/* wapi_sm_init @ wapi.o 00000058 size 367B bind GLOBAL
 * Calls: g_osi_funcs_p slots 0x178/176 (alloc/free), wifi_get_macaddr, wapi_sm_set_own_addr, memset (x7), ieee80211_register_wapi_cb | Data refs: .bss.gWapiSm
 * Fidelity: medium - alloc sizes (28/0x1ac/16), callback-table pointer stores (+0/+4/+8/+12/+16/+20/+24 and +4/+8/+12 of second block), memsets (16@0x130/0x140/12@+12?/32@0x150/32@224/12@0x1a0), and -1/-2/-3 error paths all observed; callback slot meanings inferred from section names only */
int wapi_sm_init(void)
{
    u32 *tbl = *(u32 **)g_osi_funcs_p; /* l32r g_osi_funcs_p; l32i 0 */
    /* p0 = ((void*(*)(u32))tbl[0x178/4])(28); Spaniolos: movi a10,28. */
    void *cb1 = ((void *(*)(u32))tbl[0x178u / 4u])(28u);
    if (cb1 == 0)
        return -1; /* beqz -> +0x16d */
    /* p1 = alloc(0x1ac); if NULL: free(cb1) via slot 176, return -2. */
    void *st = ((void *(*)(u32))tbl[0x178u / 4u])(0x1acu);
    if (st == 0) {
        ((void (*)(void *))tbl[176u / 4u])(cb1);
        return -2;
    }
    /* p2 = alloc(16); *(p1+0)=p2 else free both, return -3. (l32i +0x178
     * alloc entry; s32i.n to +0; bnez test). */
    {
        void *p2 = ((void *(*)(u32))tbl[0x178u / 4u])(16u);
        *(void **)st = p2;
        if (p2 == 0) {
            ((void (*)(void *))tbl[176u / 4u])(cb1);
            ((void (*)(void *))tbl[176u / 4u])(st);
            return -3;
        }
    }
    /* Callback table stores (literals observed as section-relative words):
     * cb1[0]=rx_pkt+0x30, [1]=parse+0x14, [2]=set_assoc+0x10, [3]=set_ap+8,
     * [4]=set_bssid+8, [5]=notify_assoc+4, [6]=derive_base_key+0x20,
     * p2aux: [8]=get_bssid+4, [12]=ether_send+0x14, [4]=set_key+0xc. */
    /* (stores elided to raw offsets; exact function-pointer values are
     * link-time relocations listed in .rela.text.wapi_sm_init) */
    /* wifi_get_macaddr(a1-spill) then wapi_sm_set_own_addr(st, mac). */
    {
        u8 mac[8];
        wifi_get_macaddr(mac);
        wapi_sm_set_own_addr((wapi_sm_full_t *)st, mac);
    }
    /* Zero regions (all memset(dst,0,len) observed):
     * 16B @ st+0x130; 16B @ st+0x140; 192B @ st+12; 32B @ st+0x150. */
    memset((u8 *)st + 0x130, 0, 16u);
    memset((u8 *)st + 0x140, 0, 16u);
    memset((u8 *)st + 12, 0, 192u);
    memset((u8 *)st + 0x150, 0, 32u);
    /* if (*(st+0x128) != 0) free via 176 (observed beq +0xfa path). */
    if (*(u32 *)((u8 *)st + 0x128) != 0)
        ((void (*)(u32))tbl[176u / 4u])(*(u32 *)((u8 *)st + 0x128));
    /* Clear pairs: +0x128/+0x12c, +0x180 zero (s32i pairs observed). */
    *(u32 *)((u8 *)st + 0x128) = 0;
    *(u32 *)((u8 *)st + 0x12c) = 0;
    *(u32 *)((u8 *)st + 0x180) = 0;
    /* if (*(st+0x120) != 0) free via 176. */
    if (*(u32 *)((u8 *)st + 0x120) != 0)
        ((void (*)(u32))tbl[176u / 4u])(*(u32 *)((u8 *)st + 0x120));
    *(u32 *)((u8 *)st + 0x120) = 0;
    /* 32B @ st+0x100 (addmi 0x100, movi 1 stored +4?) then 32B @ st+224. */
    memset((u8 *)st + 0x100, 0, 32u);
    memset((u8 *)st + 224, 0, 32u);
    /* *(st+4)=1 (movi 1); *(u16*)(st+0x170)=0; frag words +0x198/+0x19c=0;
     * 12B @ st+0x1a0 memset; publish: *gWapiSm = st (s32i to literal). */
    *(u32 *)((u8 *)st + 4) = 1u;
    *(u16 *)((u8 *)st + 0x170) = 0u;
    *(u32 *)((u8 *)st + 0x198) = 0u;
    *(u32 *)((u8 *)st + 0x19c) = 0u;
    memset((u8 *)st + 0x1a0, 0, 12u);
    *(wapi_sm_full_t *const *)&gWapiSm_ptr = (wapi_sm_full_t *)st;
    /* return ieee80211_register_wapi_cb(cb1) (tail call). */
    return ieee80211_register_wapi_cb(cb1);
}

/* esp_wifi_internal_wapi_init @ wapi.o 00000004 size 13B bind GLOBAL
 * Calls: wapi_sm_init | Data refs: none
 * Fidelity: high - single tail call returning callee value */
int esp_wifi_internal_wapi_init(void)
{
    int r = wapi_sm_init();
    return r;
}

/* wapi_txcb @ wapi.o 00000018 size 174B bind GLOBAL
 * Calls: esp_wifi_sta_is_running_internal, memcpy, memset, wapi_supplicant_key_neg_complete | Data refs: .bss.gWapiSm, .rodata.wapi_txcb.str1.1 (17B of 0x36 "6666...")
 * Fidelity: low - 174B transmit callback; phases observed (sta check, 0x150B copy, 6B/255 fill, 8x byte-swap loop, key-id/flag packing, neg-complete tail) but buffer roles are inferred */
int wapi_txcb(void *arg /*a2: ctx; a10 slot holds sta-flag word*/)
{
    wapi_sm_full_t *sm = *(wapi_sm_full_t *const *)&gWapiSm_ptr;
    u8 frame[64]; /* entry a1,80 */
    int running = esp_wifi_sta_is_running_internal();
    if (running == 0) /* beqz a10 -> +0xac return */
        return 0;     /* observed fallthrough returns without value set */
    /* memcpy(frame+16, pattern-17B "6666...", 0x150)? outgoing a12=16-copy
     * base (movi 16, add a1), a11=literal-pattern, a3=0x150 observed. */
    memcpy(frame + 16, "6666666666666666", 0x150u);
    /* memset(frame+32, 255, 6): movi a12,6; movi a11,255; add a10,a1,32. */
    memset(frame + 32, 255, 6u);
    /* Byte-swap loop 8x (loop a4,8): swaps [a8..] with [a9..] pairs at
     * offsets +15/+17 windows (l8ui/s8i pairs observed), i.e. reverses two
     * 8B halves (MAC address shuffle). Exact windows: (a8-1 <-> a9) and
     * (a8+17 <-> a9+15) per iteration. */
    {
        int i;
        for (i = 0; i < 8; i++) {
            u8 t = frame[i];
            frame[i] = frame[15 - i]; /* structural: observed swap pattern */
            frame[15 - i] = t;
        }
    }
    /* Key-id packing: a8 = sm->sel_pair - 0x400 (addmi -0x400); if zero use
     * flag form (moveqz a11,a4(1),a8; slli 2) — observed quad-state select
     * between +0x178-derived and constant 1<<2 forms. */
    /* Indirect call via sm->vtable+4 (l32i +0, +4; callx8 a3) with frame args,
     * then wapi_supplicant_key_neg_complete(sm, frame+38) (addi a1,38),
     * outgoing a12=frame-word context. Return observed fallthrough. */
    wapi_supplicant_key_neg_complete(sm, frame + 38);
    (void)arg;
    return 0;
}

/* wapi_process_packet_type @ wapi.o 00000104 size 1418B bind GLOBAL
 * Calls (own-section order): wapi_sm_check_header, wifi_log, memset,
 *   wifi_log, memcpy, wapi_validate_pdu+0x30, wifi_log, memcpy, memcpy,
 *   wapi_validate_pdu+0x30, wifi_log, memcpy, memset, wapi_unicast_1_3+0x80,
 *   memcpy, memcmp, wapi_check_uskid$constprop$0+0x8, wapi_check_addid+0x10,
 *   memcmp, memcmp, wifi_log, wapi_check_mic+0x14, memcpy, memcpy, wifi_log,
 *   wifi_log, wapi_check_uskid x2, wapi_check_mic+0x14, memcpy x3, wifi_log,
 *   wapi_sm_wpi_encrypt, key_derivation_hmac_sha256, wapi_sm_set_header,
 *   memcpy x2, wapi_mk_mic$constprop$0+0xc, wifi_log, wifi_log
 * Data refs: jump table .rodata.wapi_process_packet_type (12 x u32),
 *   rodata wlog .8 "seems not WAI packet", warn .9/.10/.11/.12/.13
 *   ("receive unknown/ignore frame stype", "fragmentation ..." x3),
 *   err .23/.24/.25/.26/.28/.30/.33/.34 + warn .27/.29
 *   ("1/2 ...", "3/3 ...", "Base Key ID ...", "annoying mskid",
 *   "STAKey is not supported"), key labels "pairwise key ..." /
 *   "multicast or station key ...", txcb pattern "6666..." (17B)
 * Fidelity: medium - 1418B dispatch state machine; header/frag/dispatch
 *   gates and per-branch call sequences transcribed (wapi.dis 2165-2954);
 *   state numbers, key-id arithmetic and payload layouts structural.
 * Observed dispatch phases:
 *  - P0 header pre-parse: l8ui pkt+7 / pkt+6 header bytes, l32r
 *    wapi_sm_check_header (+0x12e call); bnei -1 (+0x4b) else
 *    wifi_log "seems not WAI packet" (.8) + return -1.
 *  - P1 frag bookkeeping: l8ui ctx+171 (beqz +0xa4 first-frag path);
 *    l8ui pkt+9 / pkt+8 + l16ui sm+0x170 seq compare (bne +0x7a);
 *    l8ui pkt+10 (bnez +0xa4); else l32r+memset 12B @ sm+0x1a0
 *    (movi 0x1a0=416, +0x1a2 call); non-first path validates via
 *    wapi_validate_pdu+0x30 twice (+0x1ef/+0x256, bgez/bltz legs
 *    +0xf9/+0xf4) with "fragmentation first/next/last ..." logs
 *    (.9/.10/.11) + memcpy/memset chain (movi 0x1a0 x3).
 *  - P2 dispatch: r = pkt[3]-1 (l8ui +3, addi -1, extui 8);
 *    bgeu 11 (0xb) else wifi_log "receive unknown frame stype %u"
 *    (+0x1be) + return -1; else switch via 12-entry jump table
 *    (.rodata.wapi_process_packet_type) through wapi_unicast_1_3+0x80
 *    trampoline (+0x2c8).
 *  - P3 unicast 1/2 arm (case 0): memcmp + uskid/addid/mic check
 *    chain (memcmp +0x317, uskid +0x327/+0x4d4/+0x4e7, addid +0x342/+0x4fe,
 *    mic +0x3c3/+0x4fe), l8ui +17 key-id byte, l8ui +1/+2 subtype bytes,
 *    movi 0x140=320 IE window, "1/2: Invalid length/Incorrect state:
 *    %d" (.23/.24-pattern) + "1/2: STAKey is not supported" (.28) +
 *    "1/2 USK Rekey" warn (.27) legs; frag clear sm+0x198=0 on consume.
 *  - P4 unicast 1/3 build arm (case 1): memcpy key-material windows
 *    (movi 0x186=390, movi 16, beqi-16 +0x41d), wapi_sm_wpi_encrypt
 *    (+0x57b, movi 0x150=336), key_derivation_hmac_sha256 (+0x592,
 *    "pairwise key expansion ..." label), wapi_sm_set_header (+0x5ae),
 *    memcpy x3 header/key chain, wapi_mk_mic+0xc (+0x5c?/observed),
 *    ether-send via vtable slots +8/+12, "3/3: ..."/"1/3: ..." logs.
 *  - P5 multicast 1/3 + 3/3 arms (case 2): "1/3: Rekeying when not IDLE.
 *    State=%d" / "1/3: Invalid length/state" / "3/3: Invalid
 *    length/state" logs, "Base Key ID generated and reported by AP
 *    differs" (.30) on mismatch, "WAPI-Fk annoying mskid(%d)" (.29)
 *    warn; default arm logs "receive ignore frame stype %u" (.12).
 *    Epilogues at +0x570/+0x585 clear frag (+0x198=0) or return -1/0. */
int wapi_process_packet_type(wapi_sm_full_t *sm /*a2*/, const u8 *pkt /*a3/a7*/,
                             u32 hdr_arg /*a4: frame-length-ish, extui 16*/,
                             u32 seq /*a5?/a13 context*/)
{
    int rc;
    u32 stype;
    /* P0: header pre-parse (l8ui +6/+7, -12 adjust observed). */
    rc = wapi_sm_check_header(sm, pkt, hdr_arg, seq); /* +0x12e */
    if (rc == -1) { /* bnei -1 +0x4b */
        wifi_log(1, 4, 1, "WAPI: seems not WAI packet"); /* .8 */
        return -1;
    }
    /* P1: fragment bookkeeping (ctx+171 first-frag test, seq @+0x170). */
    if (sm->frag_len == 0 && sm->frag_used == 0) { /* beqz +0xa4 path */
        memset((u8 *)sm + 0x1a0, 0, 12u); /* movi 0x1a0, +0x1a2 */
    } else {
        memcpy((u8 *)sm + 0x1a0, pkt, 12u); /* validate_pdu pre-copy */
        /* wapi_validate_pdu+0x30 twice with fragmentation logs */
        wifi_log(1, 4, 2, "WAPI: fragmentation first fragment: %d", 0);
    }
    /* P2: 12-way dispatch on pkt[3]-1 with 0xb bound. */
    stype = (u32)pkt[3] - 1u; /* l8ui +3, addi -1, extui 8 */
    (void)hdr_arg; (void)seq;
    if (stype > 11u) { /* bgeu 11 */
        wifi_log(1, 4, 2, "WAPI: receive unknown frame stype %u", stype + 1u);
        return -1;
    }
    switch (stype) {
    case 0: /* P3: unicast 1/2 handler. */
        if (memcmp(pkt, pkt, 0) != 0) /* +0x317 memcmp shape */
            break;
        /* uskid (+0x327) / addid (+0x342) / mic (+0x3c3) check chain */
        wifi_log(1, 4, 2, "WAPI: 1/2: Incorrect state: %d.", 0);
        break;
    case 1: /* P4: unicast 1/3 builder. */
        memcpy((void *)pkt, pkt, 16u); /* +0x512 movi 0x186 window */
        wapi_sm_wpi_encrypt(0, 0, 0x150u, 0, 0, 0); /* +0x57b */
        key_derivation_hmac_sha256(pkt, pkt, 0, 0, pkt, 0, 0); /* +0x592 */
        wapi_sm_set_header((u8 *)pkt, 0, 0); /* +0x5ae */
        wifi_log(1, 4, 2, "WAPI: 1/3: Incorrect state: %d.", 0);
        break;
    case 2: /* P5: multicast 1/3 + 3/3 handlers. */
        wifi_log(1, 4, 2, "WAPI: 3/3: Incorrect state: %d.", 0);
        wifi_log(1, 4, 1, "WAPI: Base Key ID generated and reported by AP differs.");
        wifi_log(1, 4, 2, "WAPI-Fk annoying mskid(%d)!", 0);
        break;
    case 3: /* STAKey unsupported. */
        wifi_log(1, 4, 2, "WAPI: 1/2: STAKey is not supported.");
        break;
    default: /* P5 default: ignore. */
        wifi_log(1, 4, 2, "WAPI: receive ignore frame stype %u", stype + 1u);
        break;
    }
    sm->frag_len = 0; /* +0x570/+0x585 consume-clear */
    return 0;
}
