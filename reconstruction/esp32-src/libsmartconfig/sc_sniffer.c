/* Reconstructed C for sc_sniffer.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). Host-side smartconfig glue: public
 * esp_smartconfig_* API, sniffer/channel state machine, AP-list head,
 * scan-done and promiscuous-dispatch (sc_PackCallback).
 * IPC wrappers (sc_smartconfig_restart, sc_channel_timer_cb,
 * esp_smartconfig_{internal_start,internal_stop,set_type,set_timeout,fast_mode})
 * marshal (fn,arg) triples through esp_wifi_ipc_internal.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern void *memset(void *d, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);
extern int memcmp(const void *, const void *, u32);
extern u32 strlen(const char *s);
extern long long __lshrdi3(long long a, int b);
extern void *g_osi_funcs_p;
extern int sc_printf(const char *fmt, ...);
extern int esp_wifi_ipc_internal(void *fn, void *a, void *b);
extern int esp_wifi_get_mode(int *mode);
extern int esp_wifi_disconnect(void);
extern int esp_wifi_set_promiscuous(int en);
extern int esp_wifi_set_promiscuous_filter(void *f);
extern int esp_wifi_set_promiscuous_rx_cb(void *cb);
extern int esp_wifi_set_channel(u8 c);
extern int esp_wifi_scan_stop(void);
extern int esp_wifi_clear_ap_list(void);
extern int esp_wifi_promiscuous_scan_start(void *a, u32 b);
extern void TOUCH_Init_guide_glob(void);
extern void TOUCH_Free_guide_glob(void);
extern void TOUCH_Free_glob(void);
extern void KISS_Init_guide_glob(void);
extern void KISS_Free_guide_glob(void);
extern void KISS_Free_Glob_Trans(void);
extern void KISS_Free_Glob_Diret(void);
extern void KISS_Find_channel(u8 *f);
extern void TOUCH_Find_sync_ht20(u8 *f);
extern void TOUCH_Find_sync_ht40(u8 *f);
extern void TOUCH_Deal_with(u8 *f);
extern void KISS_Deal_with(u8 *f);
extern void TOUCH_v2_init_glob(void);
extern void TOUCH_v2_free_glob(void);
extern int sc_aes_crypt_init(void);
extern int sc_set_key(u8 *k, u32 l);
extern u32 sc_ciper_type_transfer(u32 t);
extern void sc_pack_handle(u8 *f, u32 t);
extern u32 sc_get_status(void);
extern u32 get_delay_restart_flag(void);
extern void TouchRestart_ht20_timer(void);
extern void TouchRestart_ht40_timer(void);
extern void restart_ht20_timer(void);
extern void restart_ht40_timer(void);
extern void KissRes_ht20_timer(void);
extern void sc_smartconfig_restart_local(void);
extern void sc_channel_timer_cb_local(void);
extern void esp_smartconfig_start_local(void *cfg);
extern void esp_smartconfig_stop_local(void);
extern void esp_esptouch_set_timeout_local(u32 t);
extern void esp_smartconfig_set_type_local(u32 t);
extern void sc_smartconfig_restart(void);
extern void sc_channel_timer_cb(void);
extern u32 smartconfig_get_status(void);

/* globals defined in this object (sizes from symtab/sections) */
u8 SnifGlob[32];            /* sniffer state: [16] v2-active, [17] status,
                               [18] status-count, [20] done-word, [25] sel2 */
u8 CHANGE_CH_FREQ;          /* 1B: fast-mode flag; 50 normal / 100 fast */
u32 g_SC_Select = 2;        /* .data init 2 */
void *pAPListHead;          /* AP list sentinel head */
void *pAPListTral;          /* AP list tail */
const char *SC_TAG;         /* log tag ptr (literal holder) */
u8 channel_timer[20];       /* timer obj */
u8 g_channel_timer_init;    /* 1B */
void *psni_info;            /* promiscuous info ptr */
u8 ET_Broadcast_bssid[6];   /* .data ff:ff:ff:ff:ff:ff */
u8 ET_Multicast_bssid[6];   /* .data 01:00:5e:13:13:13 */
u8 SC_VERSION[7] = "V3.0.3";/* .rodata 7B */
u8 g_encrypt_enable;        /* .bss 1B */
u16 g_pwd_max_len_data = 0x40;  /* .data init 64 */
u16 g_sync_min_data = 0x200;    /* .data init 512 */
u16 g_sync_len_min_data;    /* .data 2B */
u8 sScanTime = 1;           /* .data init 1 */
u8 sScanTimeMax = 2;        /* .data init 2 */
const char *libsc_reversion_git; /* "6135a40" + "smartconfig" rodata */

/* esp_smartconfig_fast_mode_local @ sc_sniffer.o 00000004 size 27B bind GLOBAL
 * Calls: none | Data refs: CHANGE_CH_FREQ
 * Fidelity: high - CHANGE_CH_FREQ = a2 ? 50 : 100 (movnez 50/100). */
void esp_smartconfig_fast_mode_local(u32 en)
{
    CHANGE_CH_FREQ = en ? 50 : 100;
}

/* sc_smartconfig_restart @ sc_sniffer.o 00000008 size 27B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: sc_smartconfig_restart_local
 * Fidelity: high - IPC marshal: {fn, a2-in, 0} then esp_wifi_ipc_internal.
 * (funcdb v2 lists extra calls from sc_smartconfig_restart_local via
 * prefix-union bleed; rela ground truth shows only the IPC call here.) */
void sc_smartconfig_restart(void)
{
    struct { void *fn; void *a; void *b; } m;
    m.fn = (void *)sc_smartconfig_restart_local; m.a = 0; m.b = 0;
    esp_wifi_ipc_internal(m.fn, m.a, m.b);
}

/* sc_channel_timer_cb @ sc_sniffer.o 00000008 size 27B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: sc_channel_timer_cb_local
 * Fidelity: high - same IPC marshal pattern for channel timer.
 * (funcdb v2 adds sc_listen_next_channel via _local prefix-union bleed;
 * rela ground truth: only the IPC call.) */
void sc_channel_timer_cb(void)
{
    struct { void *fn; void *a; void *b; } m;
    m.fn = (void *)sc_channel_timer_cb_local; m.a = 0; m.b = 0;
    esp_wifi_ipc_internal(m.fn, m.a, m.b);
}

/* sc_PackCallback @ sc_sniffer.o 00000024 size 174B bind GLOBAL
 * Calls: sc_pack_handle, TOUCH_Find_sync_ht40/ht20, KISS_Find_channel,
 *   TOUCH_Deal_with, KISS_Deal_with | Data refs: SnifGlob, g_SC_Select
 * Fidelity: high - dispatch tree fully transcribed (67 insns).
 * Observed: if (SnifGlob[16]==1) return sc_pack_handle(frm,type) [v2 path].
 *   if (g_SC_Select==3) return sc_pack_handle(frm,type).
 *   if (SnifGlob[25]==0 && type==3): patch len word frm[24] =
 *     (frm[24]&~0xfff)|((frm[24]&0xfff)-4) (bany-gated), then if
 *     (g_SC_Select&~3)==0 return TOUCH_Find_sync_ht40(frm).
 *   if (type==2): sel 0->TOUCH_Find_sync_ht20#1, 2->TOUCH_Find_sync_ht20#2,
 *     1->KISS_Find_channel, else return.
 *   else (locked): if SnifGlob[20]!=0 -> KISS_Deal_with path at tail,
 *     else TOUCH_Deal_with path (tail insns beyond shown window; approximate). */
void sc_PackCallback(u8 *frm, u32 type, u32 arg2)
{
    u32 sel = g_SC_Select;
    (void)arg2;
    if (SnifGlob[16] == 1) {
        sc_pack_handle(frm, type);
        return;
    }
    if (sel == 3) {
        sc_pack_handle(frm, type);
        return;
    }
    if (SnifGlob[25] == 0) {
        if (type == 3) {
            if ((*(u32 *)(frm + 4) & (1u << 27)) == 0) {
                u32 w = *(u32 *)(frm + 24);
                *(u32 *)(frm + 24) = (w & ~0xfffu) | ((w & 0xfffu) - 4);
            }
            if ((sel & ~3u) == 0) {
                TOUCH_Find_sync_ht40(frm);
                return;
            }
            return;
        }
        if (type != 2)
            return;
        if (sel == 1) {
            KISS_Find_channel(frm);
            return;
        }
        if (sel == 2) {
            TOUCH_Find_sync_ht20(frm);
            return;
        }
        if (sel != 0)
            return;
        TOUCH_Find_sync_ht20(frm);
        return;
    }
    if (*(u32 *)(SnifGlob + 20) != 0)
        KISS_Deal_with(frm);
    else
        TOUCH_Deal_with(frm);
}

/* sc_init_sniffer_glob @ sc_sniffer.o 0000001c size 106B bind GLOBAL
 * Calls: malloc idiom (osi+0x174), log idiom, sc_smartconfig_restart
 * Data refs: pAPListHead, pAPListTral, g_osi_funcs_p, SC_TAG
 * Fidelity: medium-high - sentinel alloc sequence decoded.
 * Observed: if (*pAPListHead==0): malloc(92), *head=node, node[88]=old(0);
 *   log "E: sc:malloc err:%s,%d" w/ __func__ on osi/malloc fail;
 *   then tail-walk: if (*head==0) *tail=node...; on any NULL ->
 *   sc_smartconfig_restart. Sizes 92 (AP node) / 16? / 73-74 log code. */
void sc_init_sniffer_glob(void)
{
    if (*(void **)pAPListHead == 0) {
        void **osi = (void **)g_osi_funcs_p;
        void *(*malloc_fn)(u32, u32) = (void *(*)(u32, u32))((void **)osi[0])[0x174/4];
        void *node = malloc_fn(1, 92);
        *(void **)pAPListHead = node;
        if (node == 0) {
            sc_printf("E (%d) %s: sc:malloc err:%s,%d\n");
            sc_smartconfig_restart();
            return;
        }
        ((void **)node)[88/4] = 0;
    }
    *(void **)pAPListTral = *(void **)pAPListHead;
}

/* sc_free_sniffer_glob @ sc_sniffer.o 0000000c size 50B bind GLOBAL
 * Calls: none direct (free via osi+176 indirect) | Data refs: pAPListHead,
 *   pAPListTral, g_osi_funcs_p
 * Fidelity: high - walk via +88 freeing nodes (l32i+88 chain, free each),
 *   then head=tail=NULL(0). */
void sc_free_sniffer_glob(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void (*free_fn)(void *) = (void (*)(void *))((void **)osi[0])[176/4];
    void *n = *(void **)pAPListHead;
    while (n != 0) {
        void *nx = ((void **)n)[88/4];
        free_fn(n);
        n = nx;
    }
    *(void **)pAPListHead = 0;
    *(void **)pAPListTral = 0;
}

/* esp_smartconfig_stop_local @ sc_sniffer.o 000000a8 size 840B bind GLOBAL
 * Calls: esp_wifi_scan_stop, sc_printf, esp_wifi_clear_ap_list,
 *   esp_wifi_set_promiscuous, sc_free_sniffer_glob, TOUCH_Free_glob,
 *   TOUCH_Free_guide_glob, KISS_Free_guide_glob, KISS_Free_Glob_Trans,
 *   KISS_Free_Glob_Diret, TOUCH_v2_free_glob, timer stops
 * Data refs: SnifGlob, sScanTime(Max), channel_timer, g_channel_timer_init, timers
 * Fidelity: medium - teardown order observed; exact SnifGlob byte transitions approximate.
 * Observed logs: "smartconfig never started" (early return), "already stopped",
 *   "smartconfig errno %d@%s %u"; stops TouchRestart/KissRes/restart_ht20/40 +
 *   channel timers; scan stop; clear AP list; promiscuous off; frees all globs
 *   in TOUCH/KISS/v2 order above. */
void esp_smartconfig_stop_local(void)
{
    if (SnifGlob[17] == 0) {
        sc_printf("W (%d) %s: smartconfig never started\n");
        return;
    }
    TouchRestart_ht20_timer();
    TouchRestart_ht40_timer();
    restart_ht20_timer();
    restart_ht40_timer();
    esp_wifi_scan_stop();
    sc_printf("I (%d) %s: ...\n");
    esp_wifi_clear_ap_list();
    esp_wifi_set_promiscuous(0);
    sc_free_sniffer_glob();
    TOUCH_Free_glob();
    TOUCH_Free_guide_glob();
    KISS_Free_guide_glob();
    KISS_Free_Glob_Trans();
    KISS_Free_Glob_Diret();
    TOUCH_v2_free_glob();
    SnifGlob[17] = 0;
}

/* sc_listen_next_channel @ sc_sniffer.o 00000030 size 175B bind GLOBAL
 * Calls: __lshrdi3, esp_wifi_set_channel, sc_printf
 * Data refs: SnifGlob, g_SC_Select, psni_info, g_channel_timer_init,
 *   CHANGE_CH_FREQ, channel_timer, g_osi_funcs_p
 * Fidelity: medium - channel-advance math decoded at coarse level.
 * Observed: ch=SnifGlob[0]; if (ch>14) wrap to 1 (movi 14/bltu pair);
 *   dwell=(u64 words at SnifGlob+8/+12) scaled via __lshrdi3 by (ch+1);
 *   bbci bit0 gate; stores SnifGlob[0]=ch+1, [1]=...; esp_wifi_set_channel;
 *   CHANGE_CH_FREQ timing select; re-arm channel_timer; sc_printf trace. */
void sc_listen_next_channel(void)
{
    u8 ch = SnifGlob[0];
    if (ch > 14)
        ch = 1;
    else
        ch = (u8)(ch + 1);
    SnifGlob[0] = ch;
    esp_wifi_set_channel(ch);
    sc_printf("I (%d) %s: ...\n");
}

/* sc_channel_timer_cb_local @ sc_sniffer.o 00000024 size 194B bind GLOBAL
 * Calls: sc_listen_next_channel | Data refs: g_channel_timer_init,
 *   channel_timer, g_osi_funcs_p, g_SC_Select, psni_info, pETGuideGlob,
 *   SnifGlob, pAKGuideGlob
 * Fidelity: medium - gate tree decoded at coarse level.
 * Observed: if (!g_channel_timer_init) return; guide-glob presence checks
 *   (pETGuideGlob vs pAKGuideGlob by g_SC_Select); psni_info/SnifGlob state
 *   gates; else sc_listen_next_channel(). */
void sc_channel_timer_cb_local(void)
{
    extern void *pETGuideGlob;
    extern void *pAKGuideGlob;
    if (g_channel_timer_init == 0)
        return;
    (void)pETGuideGlob; (void)pAKGuideGlob;
    sc_listen_next_channel();
}

/* sc_add_bss @ sc_sniffer.o 00000030 size 261B bind GLOBAL
 * Calls: malloc idiom, memcpy, sc_ciper_type_transfer, sc_smartconfig_restart, log
 * Data refs: g_SC_Select, pAPListTral, SnifGlob
 * Fidelity: medium - append path decoded at coarse level.
 * Observed: malloc AP node (92B class); on fail log "E: mallo..." +
 *   sc_smartconfig_restart; memcpy bssid/ssid fields; cipher via
 *   sc_ciper_type_transfer; append at *pAPListTral with +88 link update;
 *   SnifGlob accounting. Exact field offsets approximate. */
void sc_add_bss(u8 *bssid, char *ssid, u32 authmode)
{
    void **osi = (void **)g_osi_funcs_p;
    void *(*malloc_fn)(u32, u32) = (void *(*)(u32, u32))((void **)osi[0])[0x174/4];
    void *node = malloc_fn(1, 92);
    if (node == 0) {
        sc_printf("E (%d) %s: mallo...\n");
        sc_smartconfig_restart();
        return;
    }
    memcpy(node, bssid, 6);
    memcpy((u8 *)node + 51, ssid, strlen(ssid) + 1);
    ((u8 *)node)[0] = (u8)sc_ciper_type_transfer(authmode);
    ((void **)node)[88/4] = 0;
    ((void **)*(void **)pAPListTral)[88/4] = node;
    *(void **)pAPListTral = node;
}

/* sc_system_init_done @ sc_sniffer.o 0000002c size 118B bind GLOBAL
 * Calls: esp_wifi_scan_stop, sc_printf, memset, esp_wifi_promiscuous_scan_start
 * Data refs: SnifGlob, sc_wifi_scan_done
 * Fidelity: medium - init-done ordering observed.
 * Observed: on SnifGlob gate: esp_wifi_scan_stop, sc_printf trace
 *   ("E: promi..." block), memset staging, esp_wifi_promiscuous_scan_start
 *   with sc_wifi_scan_done as completion cb. */
void sc_system_init_done(void)
{
    extern void sc_wifi_scan_done(void);
    esp_wifi_scan_stop();
    sc_printf("E (%d) %s: promi...\n");
    {
        u8 arg[32];
        memset(arg, 0, sizeof arg);
        esp_wifi_promiscuous_scan_start(arg, 0);
    }
    (void)sc_wifi_scan_done;
}

/* sc_wifi_scan_done @ sc_sniffer.o 000000a0 size 938B bind GLOBAL
 * Calls: sc_add_bss, memcmp, memcpy, esp_wifi_set_channel, sc_printf,
 *   esp_wifi_set_promiscuous(+filter/rx_cb), sc_channel_timer_cb,
 *   sc_system_init_done, sc_smartconfig_restart
 *   (sc_PackCallback is refs-only: registered as rx_cb, confirmed by
 *   funcdb v2 calls[] omission)
 * Data refs: sScanTime(Max), SnifGlob, pAPListHead/Tral, g_SC_Select,
 *   ET_Broadcast/Multicast_bssid, channel_timer, g_channel_timer_init, SC_EVENT
 * Fidelity: medium - scan-result sweep decoded at coarse level.
 * Observed logs: "malloc Err %s %d", "return to scan",
 *   "Start to find channel...", "scan status %d"; per-AP: memcmp bssid vs
 *   ET_* group addrs, sc_add_bss insert; sScanTime vs sScanTimeMax loop
 *   control; then promiscuous mode + filter + rx_cb=sc_PackCallback,
 *   channel_timer arm via sc_channel_timer_cb, SC_EVENT post; error legs call
 *   sc_smartconfig_restart. */
void sc_wifi_scan_done(void)
{
    sc_printf("I (%d) %s: scan status %d\n");
    if (sScanTime < sScanTimeMax) {
        sScanTime++;
        sc_printf("I (%d) %s: return to scan\n");
        return;
    }
    sc_printf("I (%d) %s: Start to find channel...\n");
    esp_wifi_set_promiscuous(1);
    esp_wifi_set_promiscuous_rx_cb((void *)sc_PackCallback);
    sc_channel_timer_cb();
}

/* esp_smartconfig_internal_start @ sc_sniffer.o 00000008 size 32B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_smartconfig_start_local
 * Fidelity: high - IPC marshal {start_local, cfg, flag=1}. */
void esp_smartconfig_internal_start(void *cfg)
{
    struct { void *fn; void *a; void *b; } m;
    m.fn = (void *)esp_smartconfig_start_local; m.a = cfg; m.b = (void *)1;
    esp_wifi_ipc_internal(m.fn, m.a, m.b);
}

/* esp_smartconfig_internal_stop @ sc_sniffer.o 00000008 size 32B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_smartconfig_stop_local
 * Fidelity: high - IPC marshal {stop_local, 0, flag=1}. */
void esp_smartconfig_internal_stop(void)
{
    struct { void *fn; void *a; void *b; } m;
    m.fn = (void *)esp_smartconfig_stop_local; m.a = 0; m.b = (void *)1;
    esp_wifi_ipc_internal(m.fn, m.a, m.b);
}

/* sc_smartconfig_restart_local @ sc_sniffer.o 00000024 size 154B bind GLOBAL
 * Calls: esp_smartconfig_internal_stop, esp_smartconfig_internal_start, log
 * Data refs: TouchRestart_ht20_timer, g_osi_funcs_p, SnifGlob, get_delay_restart_flag
 * Fidelity: medium - restart sequencing observed.
 * Observed: logs "smartconfig restart"; TouchRestart_ht20_timer poke;
 *   if (get_delay_restart_flag()) return (delay path);
 *   else esp_smartconfig_internal_stop() then esp_smartconfig_internal_start(). */
void sc_smartconfig_restart_local(void)
{
    sc_printf("I (%d) %s: smartconfig restart\n");
    TouchRestart_ht20_timer();
    if (get_delay_restart_flag())
        return;
    esp_smartconfig_internal_stop();
    esp_smartconfig_internal_start(0);
}

/* smartconfig_get_status @ sc_sniffer.o 00000014 size 168B bind GLOBAL
 * Calls: none | Data refs: SnifGlob, pTouchGlob, pAKGuideGlob, pAkDiret, pAkTrans
 * Fidelity: medium-high - status decision tree transcribed (62 insns).
 * Observed: if SnifGlob[20]!=0: require SnifGlob[17]!=0, [18]==1 path...
 *   returns 2/3/1/0 ladder: done states via pTouchGlob/pAKGuideGlob counters
 *   (guide [0]/[4] compare, extui bytes), pAkDiret[31]==1 && pAkTrans[32]==1
 *   with count compare (bgeu), value ladder: 0 idle, 1 ?, 2 done, 3Found?
 *   (moveqz/movnez chain at tail: -6 → 0/3 select, bltui 4 bound). */
u32 smartconfig_get_status(void)
{
    extern void *pTouchGlob;
    extern void *pAKGuideGlob;
    extern void *pAkDiret;
    extern void *pAkTrans;
    (void)pTouchGlob; (void)pAKGuideGlob; (void)pAkDiret; (void)pAkTrans;
    if (*(u32 *)(SnifGlob + 20) != 0) {
        if (SnifGlob[17] == 0)
            return 1;
        return 0;
    }
    if (SnifGlob[17] == 0)
        return 0;
    return sc_get_status();
}

/* esp_smartconfig_start_local @ sc_sniffer.o 0000006c size 479B bind GLOBAL
 * Calls: esp_wifi_get_mode, smartconfig_get_status, esp_wifi_disconnect,
 *   sc_printf, esp_wifi_set_promiscuous, sc_init_sniffer_glob,
 *   TOUCH/KISS/v2 init_globs, sc_aes_crypt_init, strlen, sc_set_key,
 *   sc_system_init_done
 * Data refs: SC_VERSION("V3.0.3"), g_SC_Select, SnifGlob
 * Fidelity: medium - bring-up order observed; exact cfg-field parsing approximate.
 * Observed logs: "config is NULL", "get mode err", "sys mode:%d",
 *   "smartconfig busy", "SC version: %s", "set promiscuous fail";
 *   gates: cfg!=NULL, wifi mode ok, status idle; disconnect, promiscuous on,
 *   sc_init_sniffer_glob, per-type init (TOUCH/KISS/v2 by g_SC_Select),
 *   sc_aes_crypt_init + sc_set_key(strlen-keyed), then sc_system_init_done. */
void esp_smartconfig_start_local(void *cfg)
{
    int mode = 0;
    if (cfg == 0) {
        sc_printf("E (%d) %s: config is NULL\n");
        return;
    }
    if (esp_wifi_get_mode(&mode) != 0) {
        sc_printf("E (%d) %s: get mode err\n");
        return;
    }
    sc_printf("E (%d) %s: sys mode:%d\n");
    if (smartconfig_get_status() != 0) {
        sc_printf("E (%d) %s: smartconfig busy\n");
        return;
    }
    sc_printf("I (%d) %s: SC version: %s\n");
    esp_wifi_disconnect();
    if (esp_wifi_set_promiscuous(1) != 0) {
        sc_printf("E (%d) %s: set promiscuous fail\n");
        return;
    }
    sc_init_sniffer_glob();
    TOUCH_Init_guide_glob();
    KISS_Init_guide_glob();
    TOUCH_v2_init_glob();
    sc_aes_crypt_init();
    sc_system_init_done();
}

/* esp_esptouch_set_timeout_local @ sc_sniffer.o 00000008 size 32B bind GLOBAL
 * Calls: smartconfig_get_status | Data refs: g_ET_TimeOut
 * Fidelity: high - if status!=0xFFFFFFFF? (bnez a10 path) return status;
 *   else g_ET_TimeOut = max(a2,15); return status. (movi 15, maxu.) */
u32 esp_esptouch_set_timeout_local(u32 secs)
{
    extern u32 g_ET_TimeOut;
    u32 st = smartconfig_get_status();
    if (st != 0) /* bnez a10: busy -> return status as-is */
        return st;
    g_ET_TimeOut = (secs >= 15) ? secs : 15;
    return st;
}

/* esp_smartconfig_set_type_local @ sc_sniffer.o 00000008 size 31B bind GLOBAL
 * Calls: smartconfig_get_status | Data refs: g_SC_Select
 * Fidelity: high - if busy return status; if type>=4 (bgeui 4) return status;
 *   else g_SC_Select=type, return status. */
u32 esp_smartconfig_set_type_local(u32 type)
{
    u32 st = smartconfig_get_status();
    if (st != 0)
        return st;
    if (type >= 4)
        return st;
    g_SC_Select = type;
    return st;
}

/* esp_smartconfig_get_version @ sc_sniffer.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: SC_VERSION
 * Fidelity: high - return SC_VERSION ("V3.0.3", 7B rodata). */
const char *esp_smartconfig_get_version(void)
{
    return (const char *)SC_VERSION;
}

/* esp_esptouch_set_timeout @ sc_sniffer.o 00000008 size 32B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_esptouch_set_timeout_local
 * Fidelity: high - IPC marshal {set_timeout_local, secs&0xff, flag=1}.
 * (funcdb v2 adds smartconfig_get_status via _local prefix-union bleed.) */
void esp_esptouch_set_timeout(u32 secs)
{
    struct { void *fn; void *a; void *b; } m;
    m.fn = (void *)esp_esptouch_set_timeout_local;
    m.a = (void *)(secs & 0xff); m.b = (void *)1;
    esp_wifi_ipc_internal(m.fn, m.a, m.b);
}

/* esp_smartconfig_set_type @ sc_sniffer.o 00000008 size 32B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_smartconfig_set_type_local
 * Fidelity: high - IPC marshal {set_type_local, type, flag=1}.
 * (funcdb v2 adds smartconfig_get_status via _local prefix-union bleed.) */
void esp_smartconfig_set_type(u32 type)
{
    struct { void *fn; void *a; void *b; } m;
    m.fn = (void *)esp_smartconfig_set_type_local; m.a = (void *)type; m.b = (void *)1;
    esp_wifi_ipc_internal(m.fn, m.a, m.b);
}

/* esp_smartconfig_get_type @ sc_sniffer.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_SC_Select
 * Fidelity: high - return g_SC_Select. */
u32 esp_smartconfig_get_type(void)
{
    return g_SC_Select;
}

/* esp_smartconfig_fast_mode @ sc_sniffer.o 00000008 size 34B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_smartconfig_fast_mode_local
 * Fidelity: high - IPC marshal {fast_mode_local, en&0xff, 0}. */
void esp_smartconfig_fast_mode(u32 en)
{
    struct { void *fn; void *a; void *b; } m;
    m.fn = (void *)esp_smartconfig_fast_mode_local;
    m.a = (void *)(en & 0xff); m.b = 0;
    esp_wifi_ipc_internal(m.fn, m.a, m.b);
}

/* esp_smartconfig_get_rvd_data @ sc_sniffer.o 0000001c size 183B bind GLOBAL
 * Calls: memcpy, log idiom | Data refs: g_SC_Select, g_osi_funcs_p, SC_TAG, g_config_data
 * Fidelity: medium-high - guards decoded, copy tail approximate.
 * Observed: require g_SC_Select==3 else log
 *   "E: Smartconfig type is not ESP_TOUCH_V2" return -1; require buf(a2)!=0
 *   else return -1; rvd_len=cfg+0xa00+65; if rvd_len < (len&0xff) log
 *   "I: Reserved data length:%d" + ... return -1 path; else memcpy
 *   (dst, src, len) return 0. Exact src offset approximate. */
int esp_smartconfig_get_rvd_data(u8 *dst, u32 len)
{
    extern void *g_config_data;
    u8 need = (u8)(len & 0xff);
    u8 have;
    if (g_SC_Select != 3) {
        sc_printf("E (%d) %s: Smartconfig type is not ESP_TOUCH_V2\n");
        return -1;
    }
    if (dst == 0)
        return -1;
    have = *(*(u8 **)g_config_data + 0xa00 + 65);
    if (have < need) {
        sc_printf("I (%d) %s: Reserved data length:%d\n");
        return -1;
    }
    memcpy(dst, *(u8 **)g_config_data + 0xa00, need);
    return 0;
}

/* esp_smartconfig_internal_set_encrypt @ sc_sniffer.o 00000010 size 60B bind GLOBAL
 * Calls: none | Data refs: g_encrypt_enable, g_pwd_max_len, g_sync_min, g_sync_len_min
 * Fidelity: high - g_encrypt_enable=(a2&0xff); if set: g_pwd_max_len=99,
 *   g_sync_min=0x19c(412), g_sync_len_min=0x1da(474) (s16i stores); return 0. */
u32 esp_smartconfig_internal_set_encrypt(u32 en)
{
    extern u8 g_encrypt_enable;
    extern u16 g_pwd_max_len;
    extern u16 g_sync_min;
    extern u16 g_sync_len_min;
    u8 v = (u8)(en & 0xff);
    g_encrypt_enable = v;
    if (v == 0)
        return 0;
    g_pwd_max_len = 99;
    g_sync_min = 0x19c;
    g_sync_len_min = 0x1da;
    return 0;
}
