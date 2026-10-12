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
 * Calls: memcmp, memmove, memcpy, memset, TOUCH_Init_glob,
 *   esp_wifi_set_channel, sc_channel_timer_cb, sc_smartconfig_restart
 *   (+ tail-call into constprop End above)
 * Data refs: pAPListHead, SnifGlob, ET_Multicast/Broadcast_bssid, pETGuideGlob,
 *   g_sync_len_min, g_sync_min, pCHListTral, channel_timer, g_channel_timer_init,
 *   TouchRestart_ht20_timer, g_ET_TimeOut, Restart_delay_timer, restart_flag,
 *   pTouchGlob, SC_EVENT
 * Fidelity: low - 821-insn HT20 sync correlator abstracted; gates observed.
 * Observed packet/codec logic:
 *  - entry bssid-classify: memcmp(frm+32, ET_Multicast_bssid,3) then
 *    memcmp(frm+32, ET_Broadcast_bssid,6) with AP-list +88 walk; guide state
 *    bytes +26/+27 advanced (s8i) with count vs g_sync_min/g_sync_len_min
 *    thresholds (defaults 512; encrypt-mode 412/474).
 *  - sync-length staging via memmove/memcpy/memset; per-once logs
 *    "T|once %d %d", "save rssi:%d ,bssid:..", "iCh lock",
 *    "The password is encrypted", "T|sniffer on ch:%d, snd_ch:%d",
 *    "T|PHONE MAC:..", "T|AP MAC:..".
 *  - channel dwell/timeout: channel_timer arm via sc_channel_timer_cb gated
 *    by g_channel_timer_init; TouchRestart_ht20_timer; g_ET_TimeOut expiry ->
 *    Restart_delay_timer/restart_delay_cb/restart_flag or
 *    sc_smartconfig_restart; confirm tail = constprop End above. */
void TOUCH_Find_sync_ht20(u8 *frm)
{
    if (memcmp(frm + 32, ET_Multicast_bssid, 3) != 0)
        return;
    if (memcmp(frm + 32, ET_Broadcast_bssid, 6) != 0) {
        sc_channel_timer_cb();
        return;
    }
    sc_printf("I (%d) %s: T|once %d %d\n");
    TOUCH_Find_sync_ht20_end(frm);
}

/* TOUCH_Find_sync_ht40 @ sc_esptouch.o 00000058 size 1175B bind GLOBAL
 * Calls: TOUCH_Init_glob, memset, esp_wifi_set_channel
 * Data refs: SnifGlob, pETGuideGlob, g_sync_len_min, channel_timer,
 *   g_channel_timer_init, pTouchGlob, TouchRestart_ht40_timer,
 *   sc_smartconfig_restart, g_ET_TimeOut, g_sync_min, SC_EVENT
 * Fidelity: low - 442-insn HT40 (F|) sync correlator abstracted.
 * Observed: "F|sniffer on ch:%d,width:%d", "F|rssi:%d, ch:%d / F|head:%d"
 *   family logs; same threshold/timer skeleton as HT20 with
 *   TouchRestart_ht40_timer; ends in shared constprop confirm tail. */
void TOUCH_Find_sync_ht40(u8 *frm)
{
    sc_printf("I (%d) %s: F|sniffer on ch:%d,width:%d\n");
    TOUCH_Init_glob();
    memset(pTouchGlob, 0, 64);
    esp_wifi_set_channel(frm[0]);
    TOUCH_Find_sync_ht20_end(frm);
}

/* TOUCH_Deal_with @ sc_esptouch.o 00000204 size 6414B bind GLOBAL
 * Calls: TOUCH_Find_sync_ht20, TOUCH_Find_sync_ht40, esp_crc8, strlen, memset,
 *   memcpy, esp_wifi_set_channel, esp_wifi_set_promiscuous, memcmp,
 *   chm_get_band_from_chan
 * Data refs: pTouchGlob, pAPListHead, SnifGlob, enc_evt, g_encrypt_enable,
 *   TouchRestart_ht20/40_timer, ET_Multicast/Broadcast_bssid, restart_flag,
 *   Restart_delay_timer, g_wifi_nvs, g_pwd_max_len, SC_EVENT
 *   (restart_delay_cb is a registered timer cb: refs-only, not called here)
 * Fidelity: low - 2402-insn v1 length-codec deal loop abstracted; the phase
 *   order, codec checks and constants below are observed, slot bookkeeping
 *   is approximate.
 * Observed packet/codec logic:
 *  - frame class logs F| (find) then T| (deal): "F|%d-%d", "F|%c-%d",
 *    "F|reset ch %d", "F|SCAN SSID: %s", "F|hide reset ch:%d,width:%d",
 *    "F|all lenth: %d,pswd lenth: %d", "F|SCAN CRC SSID: %d", "F|XOR",
 *    "F|%d-%d-%d", "F|%d-%c-%d", "F|pswd: %s", "F|ssid: %s",
 *    "F|bssid: ..", then "T|%d-%d", "T|%c-%d", "T|SCAN SSID: %s",
 *    "T|all len:%d,pass len:%d", "T|scan ap: %d", "T|XOR",
 *    "T|%d-%d-%d", "T|%d-%c-%d", "T|pswd: %s", "T|ssid: %s", "T|bssid: ..".
 *  - datum/crc8 verify per length via esp_crc8; XOR-fold stage; total/pass
 *    length compare vs g_pwd_max_len (64 default, 99 encrypted);
 *    bssid confirm vs ET_* group addrs with memcmp; AP scan-list support
 *    ("T|scan ap: %d", pAPListHead walk); band gate chm_get_band_from_chan.
 *  - encrypt path (g_encrypt_enable): "The password is encrypted" leg with
 *    enc_evt[216] staging; completion posts SC_EVENT, promiscuous off
 *    ("promiscuous close fail" leg), channel fix, delay-restart register
 *    (Restart_delay_timer + restart_delay_cb) when restart_flag set. */
void TOUCH_Deal_with(u8 *frm)
{
    if (memcmp(frm + 32, ET_Broadcast_bssid, 6) != 0) {
        TOUCH_Find_sync_ht20(frm);
        return;
    }
    sc_printf("I (%d) %s: T|all len:%d,pass len:%d\n");
    (void)esp_crc8(frm, 6);
    (void)strlen((const char *)frm);
    memset(enc_evt, 0, sizeof enc_evt);
    memcpy(enc_evt, frm, 32);
    esp_wifi_set_channel(frm[0]);
    TOUCH_Find_sync_ht40(frm);
}
