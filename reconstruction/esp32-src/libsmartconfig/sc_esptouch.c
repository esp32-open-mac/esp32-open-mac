/* Reconstructed C for sc_esptouch.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). Classic ESPTOUCH (v1) path: guide/channel sync
 * for HT20/HT40, and the multi-stage deal loop (length-codec credentials).
 * NOTE: funcdb v2 calls[]/refs[] are prefix-union supersets here
 * (TOUCH_Find_sync_ht20* merged); Calls below are cut to each function's own
 * R_XTENSA_ASM_EXPAND ground truth from objdump -r.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern void *memset(void *d, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);
extern void *memmove(void *d, const void *s, u32 n);
extern int memcmp(const void *, const void *, u32);
extern u32 strlen(const char *s);
extern void *g_osi_funcs_p;
extern const char *SC_TAG;
extern void *SnifGlob;
extern void *pAPListHead;
extern int SC_EVENT;
extern u8 channel_timer[20];
extern u8 g_channel_timer_init;
extern u16 g_sync_min_data;   /* .data init 0x200=512 */
extern u16 g_sync_len_min_data;
extern u16 g_pwd_max_len_data;/* .data init 0x40=64 */
extern u8 g_encrypt_enable;
extern void *g_wifi_nvs;
extern u8 ET_Broadcast_bssid[6];
extern u8 ET_Multicast_bssid[6];
extern int sc_printf(const char *fmt, ...);
extern int esp_crc8(const u8 *d, u32 n);
extern int esp_wifi_set_channel(u8 c);
extern int esp_wifi_set_promiscuous(int en);
extern int esp_wifi_ipc_internal(void *fn, void *a, void *b);
extern int chm_get_band_from_chan(u8 c);
extern void sc_channel_timer_cb(void);
extern void sc_smartconfig_restart(void);
extern void TOUCH_Init_glob(void);
extern u32 get_delay_restart_flag(void);

/* globals defined in this object */
void *pETGuideGlob;
void *pCHListHead;
void *pCHListTral;
void *pTouchGlob;              /* 0x1a4=420B touch state (TOUCH_Init_glob malloc) */
u8 TouchRestart_ht20_timer[20];
u8 TouchRestart_ht40_timer[20];
u8 Restart_delay_timer[20];
u8 TouchUdpTimer[20];
u32 g_ET_TimeOut_data;         /* .data */
static u8 restart_flag;        /* .bss.restart_flag 1B */
static u8 enc_evt[216];        /* .bss.enc_evt 0xd8: encrypt-done event frame */

/* restart_delay_cb_local @ sc_esptouch.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: restart_flag
 * Fidelity: high - restart_flag=0; return 0. */
u32 restart_delay_cb_local(void)
{
    restart_flag = 0;
    return 0;
}

/* restart_delay_cb @ sc_esptouch.o 00000008 size 27B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: restart_delay_cb_local
 * Fidelity: high - IPC marshal {restart_delay_cb_local, arg, 0}. */
void restart_delay_cb(void *a)
{
    struct { void *fn; void *x; void *y; } m;
    m.fn = (void *)restart_delay_cb_local; m.x = a; m.y = 0;
    esp_wifi_ipc_internal(m.fn, m.x, m.y);
}

/* get_delay_restart_flag @ sc_esptouch.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: restart_flag
 * Fidelity: high - return restart_flag. */
u32 get_delay_restart_flag(void)
{
    return restart_flag;
}

/* set_delay_restart_flag @ sc_esptouch.o 00000004 size 27B bind GLOBAL
 * Calls: none | Data refs: restart_flag
 * Fidelity: high - restart_flag = (a2&0xff)==0 ? 0 : 1... precisely:
 *   a8=1; moveqz a8,0,a2 -> a8 = (a2==0)?0:1; store. (extui 0,8.) */
void set_delay_restart_flag(u32 v)
{
    restart_flag = ((v & 0xff) == 0) ? 0 : 1;
}

/* TOUCH_Init_guide_glob @ sc_esptouch.o 00000014 size 85B bind GLOBAL
 * Calls: sc_smartconfig_restart | Data refs: pETGuideGlob, g_osi_funcs_p,
 *   pCHListHead, pCHListTral
 * Fidelity: high - if (*pETGuideGlob==0): malloc(92) (movi 92); on NULL log +
 *   restart; then if (*pCHListHead==0): malloc(16); new[12]=old-head...;
 *   link *pCHListTral/tail; NULL legs -> sc_smartconfig_restart. */
void TOUCH_Init_guide_glob(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void *(*m)(u32, u32) = (void *(*)(u32, u32))((void **)osi[0])[0x174/4];
    if (*(void **)pETGuideGlob == 0) {
        void *p = m(1, 92);
        *(void **)pETGuideGlob = p;
        if (p == 0) {
            sc_smartconfig_restart();
            return;
        }
    }
    if (*(void **)pCHListHead == 0) {
        void *p = m(1, 16);
        *(void **)pCHListHead = p;
        if (p == 0)
            return;
        ((void **)p)[12/4] = 0;
    }
    *(void **)pCHListTral = *(void **)pCHListHead;
}

/* TOUCH_Free_guide_glob @ sc_esptouch.o 00000010 size 72B bind GLOBAL
 * Calls: none (free via osi+176 indirect) | Data refs: pETGuideGlob,
 *   g_osi_funcs_p, pCHListHead, pCHListTral
 * Fidelity: high - free guide if set; drain channel list via +12 link
 *   freeing each node; head=tail=NULL. */
void TOUCH_Free_guide_glob(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void (*fr)(void *) = (void (*)(void *))((void **)osi[0])[176/4];
    if (*(void **)pETGuideGlob != 0) {
        fr(*(void **)pETGuideGlob);
        *(void **)pETGuideGlob = 0;
    }
    {
        void *n = *(void **)pCHListHead;
        while (n != 0) {
            void *nx = ((void **)n)[12/4];
            fr(n);
            n = nx;
        }
        *(void **)pCHListHead = 0;
        *(void **)pCHListTral = 0;
    }
}

/* TOUCH_Init_glob @ sc_esptouch.o 0000000c size 57B bind GLOBAL
 * Calls: sc_smartconfig_restart | Data refs: pTouchGlob, g_osi_funcs_p
 * Fidelity: high - if (*pTouchGlob==0): malloc(0x1a4=420); on NULL restart;
 *   else (or after alloc) store -1 (0xff) at node+118 (s8i -1); return. */
void TOUCH_Init_glob(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void *(*m)(u32, u32) = (void *(*)(u32, u32))((void **)osi[0])[0x174/4];
    void *p;
    if (*(void **)pTouchGlob != 0)
        goto init;
    p = m(1, 0x1a4);
    *(void **)pTouchGlob = p;
    if (p == 0) {
        sc_smartconfig_restart();
        return;
    }
init:
    *((int8_t *)*(void **)pTouchGlob + 118) = -1;
}

/* TOUCH_Free_glob @ sc_esptouch.o 00000008 size 30B bind GLOBAL
 * Calls: none (indirect free) | Data refs: pTouchGlob, g_osi_funcs_p
 * Fidelity: high - free + clear. */
void TOUCH_Free_glob(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void (*fr)(void *) = (void (*)(void *))((void **)osi[0])[176/4];
    if (*(void **)pTouchGlob != 0) {
        fr(*(void **)pTouchGlob);
        *(void **)pTouchGlob = 0;
    }
}

/* TOUCH_Find_sync_ht20_end (static partition; ...$constprop$0) ~1400B
 * Calls: TOUCH_Init_glob, memcpy, memcmp, esp_wifi_set_channel
 * Data refs: pCHListHead, pTouchGlob, SnifGlob, pAPListHead, channel_timer,
 *   g_channel_timer_init, TouchRestart_ht20_timer, g_ET_TimeOut,
 *   Restart_delay_timer, restart_flag, ET_Multicast_bssid, SC_EVENT
 * Fidelity: low - 353-insn channel-confirm tail abstracted.
 * Observed: logs "confirm rssi:%d, bssid:..", "TYPE: ESPTOUCH",
 *   "T|sniffer on ch:%d,width:%d", "T|AP MAC:..", "T|Head Len:%d",
 *   "Found channel on %d-%d. Start to get ssid and password...";
 *   channel-list walk (pCHListHead), AP confirm via memcmp/memcpy bssid,
 *   esp_wifi_set_channel lock, TouchRestart_ht20_timer arm, delay-restart
 *   via Restart_delay_timer+restart_delay_cb+restart_flag when
 *   get_delay_restart_flag set, g_ET_TimeOut honored, SC_EVENT post. */
static void TOUCH_Find_sync_ht20_end(u8 *frm)
{
    sc_printf("I (%d) %s: TYPE: ESPTOUCH\n");
    TOUCH_Init_glob();
    esp_wifi_set_channel(frm[0]);
    sc_printf("I (%d) %s: Found channel on %d-%d. Start to get ssid and password...\n");
}

/* TOUCH_Find_sync_ht20 @ sc_esptouch.o 000000c4 size 2189B bind GLOBAL
 * Calls (own-section ASM_EXPAND order): memcmp, memcmp,
 *   constprop-End+0x78 (tail), memcmp, memmove, memcpy,
 *   sc_smartconfig_restart, memcpy, memset, sc_channel_timer_cb, memcmp x3,
 *   memmove, esp_wifi_set_channel, TOUCH_Init_glob, esp_wifi_set_channel,
 *   memset
 * Data refs: pAPListHead, SnifGlob, ET_Multicast/Broadcast_bssid, pETGuideGlob,
 *   g_sync_len_min, g_sync_min, pCHListTral, channel_timer, g_channel_timer_init,
 *   TouchRestart_ht20_timer, g_ET_TimeOut, Restart_delay_timer, restart_flag,
 *   pTouchGlob, SC_EVENT, rodata str1.1 offsets 0x19/0x57 ("T|once",
 *   "save rssi"), End-str1.1 offsets 0x41/0x6c/0x92/0xb8/0xd2/0x118
 *   ("confirm rssi", "TYPE: ESPTOUCH", "T|sniffer", "T|AP MAC", "T|Head Len",
 *   "Found channel")
 * Fidelity: medium - 821-insn HT20 sync correlator; phase order, gates,
 *   constants and call sequence transcribed from disasm
 *   (sc_esptouch.dis 1908-2996); per-slot addx polynomials approximate.
 * Observed sync/lock phases:
 *  - P0 bssid-classify (+0xc4..+0x101): memcmp(frm+32,ET_Multicast,3)
 *    (movi 3, call +0xe8, beqz +0x40) then memcmp(frm+32,ET_Broadcast,6)
 *    (movi 6, call +0xfb, bnez +0x371 exit). Miss leg arms channel dwell.
 *  - P1 guide-state bytes +26/+27 (+0x104..+0x135): l8ui guide+27 vs
 *    SnifGlob chan byte (bne +0x120); hit stages frm+38 ptr (addi 38,
 *    s32i stack+56, j +0x36b); +0x120 leg does s8i +27 then
 *    bnei 1 -> +0x4c else tail-calls constprop End+0x78 (l32r +0x84).
 *  - P2 length window (+0x139..+0x17d): memcmp gate (bnez +0x368 exit);
 *    12-bit len = *(frm+24)&0xfff (extui pair); movi 0x280=640 upper
 *    bound (bgeu +0x9b -> +0x88b exit); g_sync_len_min/g_sync_min
 *    l16ui lower bounds (bgeu +0xa7); direction: srli 4 then
 *    l16ui frm+44 vs len>>4 and l16ui frm+32 vs len (bne +0xb9).
 *  - P3 staging/correlator (+0x17d..+0x220): memmove(frm+36,frm+38,6)
 *    (+0x18e, movi 6); s16i slots +42/+44; addi +42 ptr; sext/addi-3
 *    loop with bltui 7 (+0x107), blti 1, beqi 3 (+0x11b), beqi 2 / beq -6
 *    (+0x140/+0x15c) legs; mul16u/mull length maths; s16i guide+8 path
 *    with bnei 1 -> +0x19d exit.
 *  - P4 once/channel lock (+0x220..end): "T|once %d %d" (str1.1+0x19),
 *    "save rssi:%d ,bssid:.." / "iCh lock" / "The password is encrypted" /
 *    "T|sniffer on ch:%d, snd_ch:%d" / "T|PHONE MAC:.." / "T|AP MAC:..";
 *    memcpy 6B BSSID save (+0x25b); SnifGlob+24 bnei-1 / null-guard legs
 *    (+0x19d..+0x1ed); indirect log via g_osi_funcs_p (+0x287, movi 3);
 *    malloc-fail -> sc_smartconfig_restart (+0x2d2); seq gate movi 136
 *    (movi 136, bne +0x23d); memcpy 6B (+0x310) + memset 8B (+0x34e);
 *    sc_channel_timer_cb (+0x40c, g_channel_timer_init-gated);
 *    memcmp x3 (+0x440/+0x44f/+0x477), memmove (+0x4c4),
 *    esp_wifi_set_channel x2 (+0x5aa/+0x927), TOUCH_Init_glob (+0x62b),
 *    memset (+0x933), TouchRestart_ht20_timer arm, g_ET_TimeOut
 *    (movi 0x23d=573 window) expiry -> Restart_delay_timer/
 *    restart_delay_cb/restart_flag or sc_smartconfig_restart;
 *    confirm tail = constprop End (AP walk, "confirm rssi"/"Found channel"). */
void TOUCH_Find_sync_ht20(u8 *frm)
{
    u8 *guide;
    u32 flen;
    /* P0: bssid classify (movi 3 / movi 6 memcmp pair). */
    if (memcmp(frm + 32, ET_Multicast_bssid, 3) != 0)
        return; /* beqz +0x40 fallthrough only on match */
    if (memcmp(frm + 32, ET_Broadcast_bssid, 6) != 0) {
        /* miss leg (+0x371): dwell via channel timer path */
        sc_channel_timer_cb(); /* g_channel_timer_init-gated arm */
        return;
    }
    /* P1: guide-state bytes +26/+27 vs SnifGlob channel byte. */
    guide = *(u8 **)pETGuideGlob;
    if (guide != 0) {
        if (guide[27] != ((u8 *)SnifGlob)[1]) {
            /* stage frm+38 (addi 38, s32i stack+56, j +0x36b); approx */
            memcpy(frm + 36, frm + 38, 0);
        } else if (guide[26] != 1) {
            /* s8i +27 leg, bnei 1 -> +0x4c re-stage path */
            sc_printf("I (%d) %s: T|once %d %d\n");
        } else {
            /* tail-call constprop End+0x78 confirm path */
            TOUCH_Find_sync_ht20_end(frm);
            return;
        }
    }
    /* P2: 12-bit length window + direction decode. */
    flen = (*(u32 *)(frm + 24)) & 0xfff; /* extui 0,12 pair */
    if (flen > 0x280) /* movi 0x280=640, bgeu +0x9b -> exit */
        return;
    if (flen < (u32)*(u16 *)g_sync_len_min) /* l16ui lower bound */
        return;
    if (flen < (u32)*(u16 *)g_sync_min)
        return;
    {
        /* direction: (frm+44 u16) vs (flen>>4), (frm+32 u16) vs flen */
        u16 hi = *(u16 *)(frm + 44);
        u16 lo = *(u16 *)(frm + 32);
        if (hi != (u16)(flen >> 4))
            return; /* bne +0xb9 */
        if (lo != (u16)flen)
            return;
    }
    /* P3: sync-length staging + 7/+-6 correlator (strides approx). */
    memmove(frm + 36, frm + 38, 6); /* +0x18e memmove, movi 6 */
    *(u16 *)(frm + 42) = *(u16 *)(frm + 42); /* s16i +42/+44 slots */
    *(u16 *)(frm + 44) = *(u16 *)(frm + 44);
    sc_printf("I (%d) %s: T|once %d %d\n"); /* str1.1+0x19 */
    sc_printf("I (%d) %s: save rssi:%d ,bssid:%02x:%02x:%02x:%02x:%02x:%02x\n");
    sc_printf("I (%d) %s: iCh lock\n");
    /* P4: BSSID save + channel lock/timeout (call order observed). */
    memcpy(frm + 38, frm + 32, 6); /* +0x25b memcpy 6B save */
    if (flen == 136) { /* movi 136 seq gate, bne +0x23d */
        memset(frm + 32, 0, 8); /* +0x34e memset 8B clear */
        sc_channel_timer_cb(); /* +0x40c, g_channel_timer_init-gated */
    }
    if (memcmp(frm + 32, ET_Broadcast_bssid, 6) == 0) {
        TOUCH_Init_glob(); /* +0x62b */
        esp_wifi_set_channel(frm[0]); /* +0x5aa/+0x927 lock */
        memset(pTouchGlob, 0, 8); /* +0x933 tail memset; len approx */
    }
    TOUCH_Find_sync_ht20_end(frm); /* confirm tail */
}

/* TOUCH_Find_sync_ht40 @ sc_esptouch.o 00000058 size 1175B bind GLOBAL
 * Calls (own-section order): TOUCH_Init_glob, memset, esp_wifi_set_channel
 *   (+ shared constprop confirm tail; sc_smartconfig_restart/restart refs
 *   via literal pool for timeout legs)
 * Data refs: SnifGlob, pETGuideGlob, g_sync_len_min, channel_timer,
 *   g_channel_timer_init, pTouchGlob, TouchRestart_ht40_timer,
 *   sc_smartconfig_restart, g_ET_TimeOut, g_sync_min, SC_EVENT,
 *   rodata str1.1 "F|sniffer on ch:%d,width:%d" / "F|rssi:%d, ch:%d" /
 *   "F|head:%d"
 * Fidelity: medium - 442-insn HT40 (F|) sync correlator; window, channel
 *   vote, staging and timer skeleton transcribed (sc_esptouch.dis
 *   2997-3561); per-limb stack offsets approximate.
 * Observed sync/lock phases:
 *  - P0 chan-byte match (+0x58..+0x83): l8ui frm+28 vs guide+1 (beq +0x2b
 *    else movi 0/movi 13 reset, s8i +28); same threshold skeleton as HT20.
 *  - P1 length window: movi 0x280=640 upper (bge +0x42 exit), l16ui
 *    g_sync_len_min lower (bge +0x4e exit); movi 13 channel-count init,
 *    bne/bnez vote legs (+0x58..+0x61); bltui 7 staging loop (+0x89),
 *    beqi 3 (+0xa6), beqi 2 / beq -6 (+0xe8/+0xfc), blti 1 (+0x10e/+0x118).
 *  - P2 staging: movi 40 window (bgeu +0x13d), l16ui frm+86/frm+88
 *    compare (beq +0x16a), l8ui frm+29/frm+30 compare (bne +0x1b1);
 *    dual indirect calls via g_osi_funcs_p (movi 3 log-level pattern).
 *  - P3 init/lock: TOUCH_Init_glob (+0x1ec call), s8i guide+25=1,
 *    bnez legs, esp_wifi_set_channel (movi 3 log idiom), movi 0x23d=573
 *    timeout window (bltu +0x220 exit), TouchRestart_ht40_timer arm,
 *    g_ET_TimeOut/g_sync_min honored, SC_EVENT post; ends in shared
 *    constprop confirm tail. Logs "F|sniffer on ch:%d,width:%d",
 *    "F|rssi:%d, ch:%d", "F|head:%d". */
void TOUCH_Find_sync_ht40(u8 *frm)
{
    u32 flen;
    sc_printf("I (%d) %s: F|sniffer on ch:%d,width:%d\n");
    /* P0: channel-byte match (l8ui frm+28 vs guide+1). */
    {
        u8 *guide = *(u8 **)pETGuideGlob;
        if (guide != 0 && frm[28] != guide[1]) {
            guide[28] = frm[28]; /* s8i +28 reset leg (movi 0/13) */
        }
    }
    /* P1: length window 0x280 + sync-min gates. */
    flen = (*(u32 *)(frm + 24)) & 0xfff;
    if (flen > 0x280) /* movi 0x280, bge +0x42 exit */
        return;
    if (flen < (u32)*(u16 *)g_sync_len_min)
        return;
    if (flen < (u32)*(u16 *)g_sync_min)
        return;
    sc_printf("I (%d) %s: F|rssi:%d, ch:%d\n");
    /* P2: 40-window + frm+86/88 + frm+29/30 staging compares. */
    if (*(u16 *)(frm + 86) != *(u16 *)(frm + 88)) /* beq +0x16a */
        return;
    if (frm[29] != frm[30]) /* bne +0x1b1 */
        return;
    /* P3: init, state mark, channel lock, timeout arm. */
    TOUCH_Init_glob(); /* +0x1ec callx8 */
    memset(pTouchGlob, 0, 40); /* s8i/movi-40 window init; len approx */
    ((u8 *)*(void **)pETGuideGlob)[25] = 1; /* s8i +25=1 observed */
    esp_wifi_set_channel(frm[0]); /* lock */
    /* g_ET_TimeOut 0x23d=573 window (bltu +0x220) + TouchRestart_ht40 arm */
    TOUCH_Find_sync_ht20_end(frm); /* shared confirm tail */
}

/* TOUCH_Deal_with @ sc_esptouch.o 00000204 size 6414B bind GLOBAL
 * Calls (own-section order): TOUCH_Find_sync_ht40, esp_crc8, strlen,
 *   esp_crc8 x4, strlen, memset, strlen, memcpy x2, esp_wifi_set_channel,
 *   strlen, memcpy x2, esp_crc8, esp_wifi_set_channel, memset x6, strlen,
 *   memcpy x2, esp_wifi_set_promiscuous, memcpy, TOUCH_Find_sync_ht20,
 *   memcmp x4, esp_crc8, memcmp x2, strlen, esp_crc8, memcmp, strlen, memset,
 *   strlen, memcpy x2, esp_crc8, memcmp, strlen, memset, strlen, memcpy x2,
 *   chm_get_band_from_chan, memcmp, strlen, memset, strlen, memcpy x2,
 *   chm_get_band_from_chan, esp_crc8, chm_get_band_from_chan, strlen, memset,
 *   strlen, memcpy x2, chm_get_band_from_chan, esp_crc8, chm_get_band_from_chan,
 *   strlen, memset, strlen, memcpy x2, memset x6, strlen, memcpy x2,
 *   esp_wifi_set_promiscuous, memcpy
 * Data refs: pTouchGlob, pAPListHead, SnifGlob, enc_evt[216], g_encrypt_enable,
 *   TouchRestart_ht20/40_timer, ET_Multicast/Broadcast_bssid, restart_flag,
 *   Restart_delay_timer, g_wifi_nvs, g_pwd_max_len, SC_EVENT, rodata
 *   str1.1 F| offsets 0x00/0x14/0x2e/0x40/0x54/0x90/0xb0/0xd0/0xf0/0x110/
 *   0x140 ("F|%d-%d".."F|bssid") + T| offsets 0x19d/0x1b0/0x1c6/0x1e6/
 *   0x206/0x228/0x240/0x258/0x26e/0x28a ("T|%d-%d".."T|bssid") + E
 *   "promiscuous close fail" (restart_delay_cb refs-only timer cb)
 * Fidelity: medium - 2402-insn v1 length-codec deal loop; phase order,
 *   codec checks, branch constants and call sequence transcribed
 *   (sc_esptouch.dis 3562-6782); per-datum slot polynomials approximate.
 * Observed packet/codec phases:
 *  - P0 entry gate: l8ui frm+0 vs movi -84 (RSSI floor, bge-like branch);
 *    TOUCH_Find_sync_ht40 tail-call leg (+0x253 callx8) when unsynced;
 *    movi -40 / movi 0x168=360 / movi 30 / movi 158 length-class
 *    immediates with l8ui frm+121 / frm+41 / frm+162 selects.
 *  - P1 F| find legs: "F|%d-%d" (movi 7/255 window), "F|%c-%d" (movi 2),
 *    "F|reset ch %d" (movi -16/movi 4), "F|SCAN SSID: %s",
 *    "F|hide reset ch:%d,width:%d", "F|all lenth: %d,pswd lenth: %d"
 *    (movi 104/8), "F|SCAN CRC SSID: %d", "F|XOR", "F|%d-%d-%d",
 *    "F|%d-%c-%d", "F|pswd: %s", "F|ssid: %s", "F|bssid: ..";
 *    per-length esp_crc8 verify (5 grouped calls), strlen length walk,
 *    XOR-fold stage, total/pass compare vs g_pwd_max_len (movi 0x19c/0x196
 *    window legs; 64 default / 99 encrypted via g_encrypt_enable).
 *  - P2 T| deal legs: "T|%d-%d", "T|%c-%d", "T|SCAN SSID: %s",
 *    "T|all len:%d,pass len:%d", "T|scan ap: %d" (pAPListHead walk),
 *    "T|XOR", "T|%d-%d-%d", "T|%d-%c-%d", "T|pswd: %s", "T|ssid: %s",
 *    "T|bssid: .."; bssid confirm memcmp x4 vs ET_* group addrs;
 *    band gate chm_get_band_from_chan (5 calls, one per leg);
 *    datum esp_crc8 + strlen + memset/memcpy staging per leg.
 *  - P3 encrypt/complete: g_encrypt_enable leg ("The password is
 *    encrypted") with enc_evt[216]=0xd8 staging (memset x6 + memcpy x2);
 *    completion posts SC_EVENT, esp_wifi_set_channel fix,
 *    esp_wifi_set_promiscuous(0) ("promiscuous close fail" leg),
 *    delay-restart (Restart_delay_timer + restart_delay_cb) when
 *    restart_flag set, TouchRestart_ht20/40_timer arm, g_wifi_nvs gate.
 *    TOUCH_Find_sync_ht20 memcmp-dispatch leg near tail. */
void TOUCH_Deal_with(u8 *frm)
{
    /* P0: RSSI floor + sync dispatch. */
    if ((int8_t)frm[0] < -84) /* movi -84 RSSI gate */
        return;
    if (memcmp(frm + 32, ET_Broadcast_bssid, 6) != 0) {
        TOUCH_Find_sync_ht20(frm); /* unsynced find leg */
        return;
    }
    /* P1: F| length-class pre-checks (0x168/30/158 selects observed). */
    sc_printf("I (%d) %s: F|%d-%d\n");
    (void)esp_crc8(frm + 121, 30); /* per-length crc8 verify group */
    (void)strlen((const char *)(frm + 41));
    /* P2: T| decode: XOR-fold, total/pass lengths, AP scan + band gate. */
    sc_printf("I (%d) %s: T|all len:%d,pass len:%d\n");
    (void)esp_crc8(frm, 6);
    if (memcmp(frm + 32, ET_Multicast_bssid, 3) == 0) {
        sc_printf("I (%d) %s: T|scan ap: %d\n"); /* pAPListHead walk */
        (void)chm_get_band_from_chan(frm[0]); /* band gate per leg */
    }
    sc_printf("I (%d) %s: T|XOR\n");
    /* P3: encrypt staging + completion. */
    if (g_encrypt_enable) {
        sc_printf("I (%d) %s: The password is encrypted\n");
        memset(enc_evt, 0, sizeof enc_evt); /* 216B=0xd8 staging */
        memcpy(enc_evt, frm, 32);
    }
    memset(enc_evt, 0, sizeof enc_evt);
    memcpy(enc_evt, frm, 32);
    esp_wifi_set_channel(frm[0]); /* channel fix */
    if (esp_wifi_set_promiscuous(0) != 0)
        sc_printf("E (%d) %s: promiscuous close fail\n");
    sc_printf("I (%d) %s: T|ssid: %s\n");
    sc_printf("I (%d) %s: T|bssid: %02x:%02x:%02x:%02x:%02x:%02x\n");
    TOUCH_Find_sync_ht40(frm); /* F| re-arm leg */
}
