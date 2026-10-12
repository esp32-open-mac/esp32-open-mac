/* Reconstructed C for sc_airkiss.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). AirKiss (WeChat) path: guide/channel find
 * (direct + transform modes), per-sequence data extract, HT20 deal loop.
 * NOTE: funcdb v2 calls[]/refs[] are prefix-union supersets here
 * (e.g. KISS_Find_channel* merged); per-function Calls below are cut to
 * each function's own R_XTENSA_ASM_EXPAND ground truth from objdump -r.
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
extern int sc_printf(const char *fmt, ...);
extern int esp_crc8(const u8 *d, u32 n);
extern int esp_wifi_set_channel(u8 c);
extern int esp_wifi_set_promiscuous(int en);
extern void sc_channel_timer_cb(void);
extern void sc_smartconfig_restart(void);
extern void KissRes_ht20_timer(void);
extern void KISS_Init_Glob_Trans(void);
extern void KISS_Init_Glob_Diret(void);
extern void KISS_Find_channel_trans(u8 *f);
extern void KISS_Find_channel_direct(u8 *f);
extern void KISS_Find_channel_end(u8 *f);

/* globals defined in this object */
void *pAKGuideGlob;        /* guide state ptr */
void *pAkTrans;            /* transform-mode state ptr */
void *pAkDiret;            /* direct-mode state ptr */
const u8 AK_Group_bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; /* .data */
u8 KissRes_ht20_timer[20]; /* timer obj */
u8 weixin_timer[20];       /* timer obj */
const u8 DATA_RSSI_BEAR = 0x12; /* .rodata 1B = 18 */
const u8 RSSI_BEAR = 0x12;      /* .rodata 1B = 18 */
const u8 RSSI_MIN = 0xab;       /* .rodata 1B = -85 signed floor */

/* forward: static sequ-data extractor (no funcdb entry; .text.KISS_Get_sequ_data) */
static u32 KISS_Get_sequ_data(u8 *frm, u8 *st);

/* KISS_Get_sequ_data (static partition) size ~1312B
 * Calls: memmove, memset, esp_crc8 | Data refs: SnifGlob, g_osi_funcs_p, SC_TAG
 * Fidelity: medium - entry gates + length window transcribed; body approximate.
 * Observed entry: require frm[28]==136 (0x88, bne reject), st[20]==1
 *   (bnei reject), u16 st[22]==byte-swapped u16 frm[52] (slli8/or/b16 compare);
 *   L=(((frm[24]&0xfff)-st[4])&0xffff); require (L-64)<=0x1bf i.e. L in
 *   [64,511] else return-fail path (0x3c4). Body: l16u compares at st+{18,32}
 *   and +88, memmove/memset staging, esp_crc8 verify, logs "T|crc","T|s..". */
static u32 KISS_Get_sequ_data(u8 *frm, u8 *st)
{
    u32 L = ((*(u32 *)(frm + 24) & 0xfff) - st[4]) & 0xffff;
    if (frm[28] != 136)
        return 0;
    if (st[20] != 1)
        return 0;
    {
        u16 got = (u16)(frm[52] | (frm[53] << 8)); /* slli8/or, approx order */
        if (*(u16 *)(st + 22) != got)
            return 0;
    }
    if ((u16)(L - 64) > 0x1bfu)
        return 0;
    sc_printf("I (%d) %s: T|crc\n");
    (void)esp_crc8(frm, 6);
    return 1;
}

/* KISS_Init_guide_glob @ sc_airkiss.o 00000014 size 78B bind GLOBAL
 * Calls: sc_smartconfig_restart | Data refs: g_osi_funcs_p, pAKGuideGlob, SC_TAG
 * Fidelity: high - if (*pAKGuideGlob==0): malloc(34) store; on NULL log
 *   "E: pAKGuideGlob not null" idiom + sc_smartconfig_restart. (movi 34.) */
void KISS_Init_guide_glob(void)
{
    if (*(void **)pAKGuideGlob == 0) {
        void **osi = (void **)g_osi_funcs_p;
        void *(*m)(u32, u32) = (void *(*)(u32, u32))((void **)osi[0])[0x174/4];
        void *p = m(1, 34);
        *(void **)pAKGuideGlob = p;
        if (p == 0) {
            sc_printf("E (%d) %s: pAKGuideGlob not null\n");
            sc_smartconfig_restart();
        }
    }
}

/* KISS_Free_guide_glob @ sc_airkiss.o 00000008 size 30B bind GLOBAL
 * Calls: none (free via osi+176 indirect) | Data refs: pAKGuideGlob, g_osi_funcs_p
 * Fidelity: high - free(*pAKGuideGlob) if set, clear. */
void KISS_Free_guide_glob(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void (*fr)(void *) = (void (*)(void *))((void **)osi[0])[176/4];
    if (*(void **)pAKGuideGlob != 0) {
        fr(*(void **)pAKGuideGlob);
        *(void **)pAKGuideGlob = 0;
    }
}

/* KISS_Init_Glob_Trans @ sc_airkiss.o 00000018 size 118B bind GLOBAL
 * Calls: sc_smartconfig_restart | Data refs: g_osi_funcs_p, pAkTrans, SC_TAG
 * Fidelity: high - if (*pAkTrans==0): malloc(216) (movi 216); on NULL log
 *   "E: pkiss head not null"/"E: Init p_listen malloc err" + restart. */
void KISS_Init_Glob_Trans(void)
{
    if (*(void **)pAkTrans == 0) {
        void **osi = (void **)g_osi_funcs_p;
        void *(*m)(u32, u32) = (void *(*)(u32, u32))((void **)osi[0])[0x174/4];
        void *p = m(1, 216);
        *(void **)pAkTrans = p;
        if (p == 0) {
            sc_printf("E (%d) %s: Init p_listen malloc err\n");
            sc_smartconfig_restart();
        }
    }
}

/* KISS_Init_Glob_Diret @ sc_airkiss.o 00000018 size 118B bind GLOBAL
 * Calls: sc_smartconfig_restart | Data refs: g_osi_funcs_p, pAkDiret, SC_TAG
 * Fidelity: high - same shape, malloc(216), "E: init p_listen malloc err". */
void KISS_Init_Glob_Diret(void)
{
    if (*(void **)pAkDiret == 0) {
        void **osi = (void **)g_osi_funcs_p;
        void *(*m)(u32, u32) = (void *(*)(u32, u32))((void **)osi[0])[0x174/4];
        void *p = m(1, 216);
        *(void **)pAkDiret = p;
        if (p == 0) {
            sc_printf("E (%d) %s: init p_listen malloc err\n");
            sc_smartconfig_restart();
        }
    }
}

/* KISS_Free_Glob_Trans @ sc_airkiss.o 00000008 size 30B bind GLOBAL
 * Calls: none (indirect free) | Data refs: pAkTrans, g_osi_funcs_p
 * Fidelity: high - free + clear. */
void KISS_Free_Glob_Trans(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void (*fr)(void *) = (void (*)(void *))((void **)osi[0])[176/4];
    if (*(void **)pAkTrans != 0) {
        fr(*(void **)pAkTrans);
        *(void **)pAkTrans = 0;
    }
}

/* KISS_Free_Glob_Diret @ sc_airkiss.o 00000008 size 30B bind GLOBAL
 * Calls: none (indirect free) | Data refs: pAkDiret, g_osi_funcs_p
 * Fidelity: high - free + clear. */
void KISS_Free_Glob_Diret(void)
{
    void **osi = (void **)g_osi_funcs_p;
    void (*fr)(void *) = (void (*)(void *))((void **)osi[0])[176/4];
    if (*(void **)pAkDiret != 0) {
        fr(*(void **)pAkDiret);
        *(void **)pAkDiret = 0;
    }
}

/* KISS_Find_channel @ sc_airkiss.o 00000014 size 62B bind GLOBAL
 * Calls: memcmp, KISS_Find_channel_trans, KISS_Find_channel_direct
 * Data refs: AK_Group_bssid
 * Fidelity: high - dispatcher fully decoded: if (!memcmp(frm+32,
 *   AK_Group_bssid,6)) KISS_Find_channel_trans(frm); else if (!memcmp(frm+44,
 *   AK_Group_bssid,6)) KISS_Find_channel_direct(frm); else return.
 * (v2's extra callees belong to the callee bodies.) */
void KISS_Find_channel(u8 *frm)
{
    if (memcmp(frm + 32, AK_Group_bssid, 6) == 0) {
        KISS_Find_channel_trans(frm);
        return;
    }
    if (memcmp(frm + 44, AK_Group_bssid, 6) == 0)
        KISS_Find_channel_direct(frm);
}

/* KISS_Find_channel_end @ sc_airkiss.o 00000068 size 719B bind GLOBAL
 * Calls: memcpy, memcmp, KISS_Init_Glob_Trans, esp_wifi_set_channel
 * Data refs: pAKGuideGlob, SnifGlob, g_osi_funcs_p, SC_TAG, pAkTrans,
 *   AK_Group_bssid, pAPListHead, channel_timer, g_channel_timer_init,
 *   KissRes_ht20_timer, SC_EVENT
 * Fidelity: medium - end-of-guide sequence decoded at coarse level.
 * Observed: memcpy 6B bssid (guide+17) to stack frame; require SnifGlob[24]==1
 *   (bnei gate) else tail; log-idiom traces "right rssi:%d bssid:..",
 *   "T|direct recved", "TYPE: AIRKISS", "T|AP MAC:..", "T|Head Len:%d",
 *   "T|sniffer on ch:%d, snd_ch:%d", "Found channel on %d-%d...";
 *   AP-list walk (memcmp vs AK_Group_bssid/pAPListHead); KISS_Init_Glob_Trans;
 *   esp_wifi_set_channel lock; KissRes_ht20_timer/channel_timer arm via
 *   g_channel_timer_init; SC_EVENT post; fail legs sc_smartconfig_restart. */
void KISS_Find_channel_end(u8 *frm)
{
    u8 bssid[6];
    memcpy(bssid, *(u8 **)pAKGuideGlob + 17, 6);
    if (((u8 *)SnifGlob)[24] != 1)
        return;
    sc_printf("I (%d) %s: TYPE: AIRKISS\n");
    if (memcmp(frm, bssid, 6) != 0)
        return;
    KISS_Init_Glob_Trans();
    esp_wifi_set_channel(frm[0]);
}

/* KISS_Find_channel_trans @ sc_airkiss.o 00000040 size 900B bind GLOBAL
 * Calls: memcmp, memmove, memcpy, memset, KISS_Find_channel_end, sc_channel_timer_cb
 * Data refs: pAPListHead, SnifGlob, pAKGuideGlob, g_osi_funcs_p, SC_TAG
 * Fidelity: medium - transform correlator decoded at coarse level.
 * Observed: AP-list sweep with memcmp/memmove staging, memset reset;
 *   logs "right:..rssi:%d", "iBssid ..", "buf ..", "iCh lock";
 *   on match KISS_Find_channel_end(frm), else channel dwell via
 *   sc_channel_timer_cb. 340 insns / 52 branches. */
void KISS_Find_channel_trans(u8 *frm)
{
    sc_printf("I (%d) %s: iCh lock\n");
    if (memcmp(frm, *(void **)pAPListHead, 6) == 0)
        KISS_Find_channel_end(frm);
    else
        sc_channel_timer_cb();
}

/* KISS_Find_channel_direct @ sc_airkiss.o 00000070 size 1088B bind GLOBAL
 * Calls: memcmp, memmove, memcpy, memset, KISS_Init_Glob_Diret, esp_wifi_set_channel
 * Data refs: pAPListHead, pAKGuideGlob, pAkDiret, SnifGlob, channel_timer,
 *   g_channel_timer_init, KissRes_ht20_timer, SC_EVENT
 * Fidelity: medium - direct correlator decoded at coarse level.
 * Observed: NULL check "E: p_kiss NULL"; phone/AP MAC logs
 *   ("T|PHONE MAC:..", "T|AP MAC:..", "T|head Len:%d",
 *   "T|sniffer on ch:%d,snd_ch:%d", "T|trans ch%d,snd_ch:%d");
 *   memmove/memcpy staging vs pAkDiret, KISS_Init_Glob_Diret on demand,
 *   esp_wifi_set_channel lock + timer arm; fail legs restart. */
void KISS_Find_channel_direct(u8 *frm)
{
    if (*(void **)pAkDiret == 0) {
        sc_printf("E (%d) %s: p_kiss NULL\n");
        return;
    }
    sc_printf("I (%d) %s: T|AP MAC:%02x:%02x:%02x:%02x:%02x:%02x\n");
    KISS_Init_Glob_Diret();
    esp_wifi_set_channel(frm[0]);
}

/* KISS_Deal_with_ht20 (static partition; .text.KISS_Deal_with_ht20) ~4000B
 * Calls: KISS_Find_channel, KISS_Get_sequ_data, memcmp, memset, esp_crc8,
 *   strlen, memcpy, esp_wifi_set_promiscuous
 * Data refs: SnifGlob, pAPListHead, KissRes_ht20_timer, SC_EVENT
 * Fidelity: low - 712-insn deal loop abstracted; codec checks observed.
 * Observed: per-seq KISS_Get_sequ_data(); crc via esp_crc8 ("T|crc");
 *   length/retain accounting logs "T|retain: %d", "T|all: %d",
 *   "T|ssid len %d", "T|bssid same", "T|SSID: %s", "T|scan: %d",
 *   "T|index:%d, remain:%d", "T|pass len: %d", "T|pswd: %s", "T|ssid: %s";
 *   bssid confirm + channel re-find via KISS_Find_channel on drift;
 *   promiscuous off ("promiscuous close fail" leg) at completion. */
static void KISS_Deal_with_ht20(u8 *frm)
{
    (void)KISS_Get_sequ_data(frm, (u8 *)SnifGlob);
    sc_printf("I (%d) %s: T|retain: %d\n");
    KISS_Find_channel(frm);
}

/* KISS_Deal_with @ sc_airkiss.o 00000014 size 52B bind GLOBAL
 * Calls: memcmp, KISS_Deal_with_ht20 (indirect tail goto in disasm)
 * Data refs: AK_Group_bssid, pAkTrans, pAkDiret
 * Fidelity: high (dispatcher) - decoded 20 insns: RSSI gate sext(frm[0]) >= -84
 *   (movi -84, blt reject); require type arg a3==2 else return; if
 *   (!memcmp(frm+32, AK_Group_bssid,6)) tail-call via *pAkTrans else via
 *   *pAkDiret into KISS_Deal_with_ht20(body). The heavy codec calls
 *   (esp_crc8/memcpy/memset/strlen/promiscuous) that funcdb v2 attributes here
 *   live in the ht20 body above (prefix-union bleed), not in this 52B stub. */
void KISS_Deal_with(u8 *frm, u32 type)
{
    int rssi = (int)((int8_t)frm[0]); /* sext bit7 */
    void *tgt;
    if (rssi < -84)
        return;
    if (type != 2)
        return;
    if (memcmp(frm + 32, AK_Group_bssid, 6) == 0)
        tgt = *(void **)pAkTrans;
    else
        tgt = *(void **)pAkDiret;
    (void)tgt;
    KISS_Deal_with_ht20(frm);
}
