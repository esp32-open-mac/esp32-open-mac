/* Reconstructed C for ESP32 libespnow.a :: manatick.o (Xtensa ELF32, windowed ABI).
 * Source: /tmp/re_esp32/libespnow/manatick.o + funcdb_libespnow.json v3 + full objdump -d -r.
 * NOTE on funcdb v3: calls[]/refs[] are exact per-function for EXTERNAL
 * (R_XTENSA_ASM_EXPAND) edges and were verified clean (no sibling-section bleed
 * in this lib). Intra-object calls to LOCAL statics (mt_clear_lmk, mt_get_lmk,
 * mt_get_key_idx, mt_set_lmk, mt_copy_peer, mt_recv_cb, mt_send_cb) use
 * section-relative literals and never appear in funcdb calls[]; those edges are
 * from disasm ground truth and marked "LOCAL edge" below.
 * OSI slots used (see espnow.c header): +84 lock(not used here), +150 log,
 * +158 timestamp, +164? no; +364 _wifi_malloc, +368? no; +376 _wifi_zalloc,
 * +172 _malloc, +176 _free.
 * Log pattern identical to espnow.c: _log_write(level,TAG,fmt,ts,TAG[,x...]).
 */
#include <stdint.h>
#include <stddef.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32;

#define ESP_OK                  0
#define ESP_ERR_NO_MEM          0x101
#define ESP_ERR_ESPNOW_ARG      0x3066
#define ESP_ERR_ESPNOW_NO_MEM   0x3067
#define ESP_ERR_ESPNOW_FULL     0x3068
#define ESP_ERR_ESPNOW_NOT_FOUND 0x3069
#define ESP_ERR_ESPNOW_INTERNAL 0x306a
#define ESP_ERR_ESPNOW_EXIST    0x306b
#define ESP_ERR_ESPNOW_IF       0x306c
#define ESP_ERR_ESPNOW_CHAN     0x306d

/* 28-byte internal peer node. Every field below has 2+ offset evidences
 * (l32i/s32i/l8ui/s8i/memcmp/memcpy immediates across mt_add/del/mod/get/
 * fetch/send/copy_peer). Unobserved bytes kept as _rsvd. */
typedef struct peer_node {
    struct peer_node *next; /* +0: list link (walks in get/del/fetch/send/info/exist) */
    struct peer_node *prev; /* +4: unlink (del), append (add) */
    u8  _06[2];             /* +6..7: unobserved */
    u8  channel;            /* +8: u8 channel (copy/add/mod store, send compare) */
    u8  ifidx;              /* +9: u8 ifidx (copy/add/set_lmk/send use) */
    u8  mac[6];             /* +10..15: peer MAC (memcmp key, copy src) */
    void *priv;             /* +16: priv ptr (copy/add/mod move it) */
    void *key;              /* +20: key-material struct* (set/clear_lmk, del frees) */
    void *rate;             /* +24: 12B rate-config* (send reads, set_rate swaps) */
} peer_node_t;              /* == 28: _wifi_malloc(28) in mt_add_peer */

/* 60-byte ESPNOW core state (.bss.g_mt, memset 60 in mt_init). */
typedef struct {
    u8  key_state[16];  /* +0..15: init to i*i in mt_init; mt_set_pmk copies 16B PMK
                         * here (rela addend g_mt+0); passed implicitly to key/crypto
                         * helpers via g_mt. Exact cell semantics need libnet80211. */
    u8  _10[12];        /* +16..27: no observed access */
    peer_node_t *head;  /* +28: list head (every peer walk) */
    peer_node_t *tail;  /* +32: list tail (add append, del unlink) */
    u32 total;          /* +36: peer count (add ++, del --, full check >= 20) */
    u32 enc_count;      /* +40: encrypted count (add/mod ++, del --, max via menuconfig) */
    peer_node_t *cursor;/* +44: fetch cursor (fetch reset/advance, del fixup) */
    void *recv_cb;      /* +48: recv cb (reg/unreg, mt_recv_cb dispatches) */
    void *send_cb;      /* +52: send cb (reg/unreg, mt_send_cb dispatches) */
    u16 wake_window;    /* +56: u16 wake window (init 0xFFFF, set_wake_window) */
    u8  _3a[2];         /* +58..59: pad */
} mt_state_t;

static mt_state_t g_mt;             /* .bss.g_mt, 0x3c bytes */
static u32 g_mt_version = 2;        /* .data.g_mt_version (observed bytes 02 00 00 00) */
static u8 g_espnow_user_oui[3] = {0x18, 0xfe, 0x34}; /* .data (observed bytes) */

typedef struct {
    u8 _p0[172];
    void *(*_malloc)(u32 size);           /* +172 */
    void (*_free)(void *p);               /* +176 */
    u8 _p1[156];
    void (*_log_write)(u32 level, const char *tag, const char *fmt, ...); /* +336 */
    void (*_log_writev)(void);            /* +340 (unobserved here; adapter.h order) */
    u32 (*_log_timestamp)(void);  /* +344 */
    u8 _p2[16];
    void *(*_wifi_malloc)(u32 size); /* +364 */
    u8 _p3[8];
    void *(*_wifi_zalloc)(u32 size); /* +376 */
} osi_t;
extern osi_t *g_osi_funcs_p;
extern u8 g_wifi_menuconfig[];  /* opaque; +80 read (enc max), +97 read (init path) */
extern u8 g_wifi_nvs[];         /* opaque capability bytes */
extern void *g_chm;             /* chm struct; byte+80 = current channel (mt_send) */
extern void *g_ic;              /* ic struct; words+16/+20 used in rate validation */
extern void *ccmp;              /* ccmp method ptr stored at keystruct+160 */
extern void *wpa_crypto_funcs;  /* crypto table; fn@16 (lmk seal), fn@20 (lmk open) */

extern void *memset(void *d, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);
extern int memcmp(const void *a, const void *b, u32 n);
extern int pp_register_tx_cb(void *cb, u32 a, u32 b);   /* observed (mt_send_cb,7,0) */
extern int pp_unregister_tx_cb(u32 a);                  /* observed (7) */
extern int register_ieee80211_action_vendor_spec_cb(void *cb);
extern int unregister_ieee80211_action_vendor_spec_cb(void);
extern int register_ieee80211_action_vendor_get_key_cb(void *cb);
extern int unregister_ieee80211_action_vendor_get_key_cb(void);
extern int esp_wifi_internal_configure_wake_window(void *p, u32 f);
extern int esp_wifi_internal_offchan_cancel(u32 f);     /* observed (1) */
extern int ieee80211_get_tx_info_from_eb(void *eb, void *info);
extern int ieee80211_send_action_vendor_spec(u32 ifidx, const u8 *mac,
        const u8 *data, u32 len, u32 x5, void *x6);
extern int ic_del_key(u32 idx);
extern int ic_set_key(u32 ifidx, u32 a3, u32 a4, const u8 *mac, u32 idx, void *key, ...);
extern int ieee80211_mt_key_clear_mask(u32 a, u32 b);
extern int ieee80211_mt_key_set_mask(u32 a, u32 b);
extern int ieee80211_mt_key_is_mask(u32 a, u32 b);
extern int ieee80211_mt_key_is_mask_zero(u32 sel);
extern int ieee80211_regdomain_check_channel(u32 ch);
extern int esp_wifi_sta_pmf_enabled(void);
extern int wifi_ap_pmf_enabled(void);
extern int chm_get_current_channel(void);
extern int chm_get_band_from_chan(u32 ch);

#define TAG_ESPNOW "ESPNOW"
static void mt_log(u32 level, const char *fmt, u32 t)
{
    osi_t *osi = g_osi_funcs_p;
    if (osi == NULL || osi->_log_write == NULL) return;
    osi->_log_write(level, TAG_ESPNOW, fmt, t, TAG_ESPNOW);
}
static void mt_logx(u32 level, const char *fmt, u32 t, u32 x)
{
    osi_t *osi = g_osi_funcs_p;
    if (osi == NULL || osi->_log_write == NULL) return;
    osi->_log_write(level, TAG_ESPNOW, fmt, t, TAG_ESPNOW, x);
}

/* mt_recv_cb @ manatick.o section+00000004 size 22B bind LOCAL
 * Calls: (none, indirect recv_cb) | Data refs: g_mt (from disasm)
 * Fidelity: high - 5-instruction dispatch trampoline, exact. */
/* NOTE: not in funcdb (local); edges from disasm. */
static void mt_recv_cb(const void *info, const u8 *data, u32 len)
{
    void (*cb)(const void *, const u8 *, u32) = g_mt.recv_cb; /* +48 */
    if (cb == NULL)
        return;
    cb(info, data, len);
}

/* mt_send_cb @ manatick.o section+0000001c size 122B bind LOCAL
 * Calls: memset, ieee80211_get_tx_info_from_eb (ASM_EXPAND, from disasm) | Data refs: g_mt, g_osi_funcs_p
 * Fidelity: high - null-eb/desc INFO logs + tx-info dispatch fully traced. */
/* NOTE: not in funcdb (local); edges from disasm. */
static void mt_send_cb(void *eb)
{
    u8 info[28];
    void (*cb)(void *, u32);
    memset(info, 0, 28);
    cb = g_mt.send_cb; /* +52 */
    if (cb == NULL)
        return;
    if (eb == NULL) {
        mt_log(3, "I (%d) %s: espnow send cb eb is null", g_osi_funcs_p->_log_timestamp());
        return;
    }
    if (*(u32 *)((u8 *)eb + 44) == 0) {
        mt_log(3, "I (%d) %s: espnow send cb eb desc is null", g_osi_funcs_p->_log_timestamp());
        return;
    }
    ieee80211_get_tx_info_from_eb(eb, info);
    cb(info, *(u32 *)(info + 24));
}

/* mt_clear_lmk @ manatick.o section+00000008 size 30B bind LOCAL
 * Calls: ic_del_key, ieee80211_mt_key_clear_mask (ASM_EXPAND, from disasm) | Data refs: (none)
 * Fidelity: high - 2-call teardown, arg offsets exact, callee semantics opaque. */
/* NOTE: not in funcdb (local); edges from disasm. */
static void mt_clear_lmk(peer_node_t *node)
{
    u8 *ks = (u8 *)node->key; /* +20 */
    ic_del_key(ks[186]);
    ieee80211_mt_key_clear_mask(node->ifidx /* +9 */, ks[186]);
}

/* mt_get_lmk @ manatick.o section+00000014 size 82B bind LOCAL
 * Calls: memcmp (ASM_EXPAND, from disasm) | Data refs: g_mt, g_osi_funcs_p
 * Fidelity: high - NULL-mac log + MAC walk returning node key ptr, exact. */
/* NOTE: not in funcdb (local); edges from disasm. */
static void *mt_get_lmk(const u8 *mac)
{
    peer_node_t *n;
    if (mac == NULL) {
        mt_log(1, "E (%d) %s: Peer addr is null", g_osi_funcs_p->_log_timestamp());
        return NULL;
    }
    for (n = g_mt.head; n != NULL; n = n->next) {
        if (memcmp(n->mac /* +10 */, mac, 6) == 0)
            return n->key; /* +20 */
    }
    return NULL;
}

/* mt_get_key_idx$constprop$0 @ manatick.o section+00000018 size 90B bind LOCAL
 * Calls: ieee80211_mt_key_is_mask x2 (ASM_EXPAND, from disasm) | Data refs: g_osi_funcs_p
 * Fidelity: medium - scan logic + 0xFFFF full sentinel exact; mask-table semantics and original (const-propagated) args need libnet80211. */
/* NOTE: not in funcdb (local, compiler-cloned constprop); edges from disasm. */
static u32 mt_get_key_idx(void)
{
    int i;
    for (i = 24; i >= 0; i--) {
        if (ieee80211_mt_key_is_mask((u32)i, 0) != 0)
            continue;
        if (ieee80211_mt_key_is_mask((u32)i, 1) != 0)
            continue;
        return (u32)i;
    }
    mt_log(1, "E (%d) %s: hw key full", g_osi_funcs_p->_log_timestamp());
    return 0xFFFF; /* literal +0 observed */
}

/* mt_set_lmk @ manatick.o section+00000040 size 272B bind LOCAL
 * Calls: memset, memcpy, ieee80211_mt_key_set_mask, esp_wifi_sta_pmf_enabled, wifi_ap_pmf_enabled, ic_set_key (ASM_EXPAND, from disasm) + mt_get_key_idx (LOCAL edge) | Data refs: ccmp, g_mt, g_osi_funcs_p, wpa_crypto_funcs
 * Fidelity: medium - control flow, keystruct offsets (0/160/168/184/185/186), FULL-on-key-exhausted, fail-log-and-continue quirk exact; crypto/ic_set_key prototypes opaque (libnet80211). */
/* NOTE: not in funcdb (local); edges from disasm. */
static int mt_set_lmk(peer_node_t *node, const u8 *lmk, u32 mode)
{
    u8 *ks = (u8 *)node->key; /* +20 */
    u32 idx;
    if (mode == 0) {
        *(u16 *)(ks + 184) = 0x310;         /* s16i observed */
        memset(ks, 0, 168);                 /* outgoing a11 = mode = 0 */
        *(void **)(ks + 160) = ccmp;
        idx = mt_get_key_idx();             /* LOCAL edge */
        if (idx == 0xFFFF)
            return ESP_ERR_ESPNOW_FULL;     /* 0x60d<<3 observed */
        ieee80211_mt_key_set_mask(node->ifidx /* +9 */, idx);
        *(u16 *)ks = (u16)idx;              /* s16i @+0 observed */
        ks[186] = (u8)idx;                  /* s8i @+186 observed */
    }
    {
        u8 tmp[16];
        void *cf = wpa_crypto_funcs;
        u8 pmf_off;
        u32 no_pmf;
        struct { u32 k184; u32 no_pmf; u32 zero; } kcfg;
        memset(tmp, 0, 16);
        if (*(void **)((u8 *)cf + 16) != NULL) {
            int cryp_ret;
            /* Seal LMK into keystruct+168 with PMK (g_mt passed, PMK @ g_mt+0). */
            memcpy(ks + 168, lmk, 16);
            cryp_ret = ((int (*)(void *, void *, void *, u32))(*(void **)((u8 *)cf + 16)))
                    (&g_mt, tmp, ks, 16);
            if (cryp_ret != 0) {
                mt_log(1, "E (%d) %s: Encryption Failed", g_osi_funcs_p->_log_timestamp());
                /* QUIRK: fail path zeroes keystruct[0..15] then still programs key. */
                memset(ks, 0, 16);
            }
        }
        /* PMF capability select -> no_pmf flag (1 when unprotected). */
        pmf_off = node->ifidx; /* +9 */
        if (pmf_off == 0) {
            no_pmf = 1;
            if (esp_wifi_sta_pmf_enabled() != 0)
                no_pmf = pmf_off; /* =0: STA PMF on */
        } else {
            no_pmf = 1;
            if (pmf_off == 1)
                no_pmf = (wifi_ap_pmf_enabled() ^ 1) & 0xff;
        }
        kcfg.k184 = ks[184]; /* l8ui observed (low byte of 0x310 marker) */
        kcfg.no_pmf = no_pmf;
        kcfg.zero = 0;
        /* 7th arg via stack stores observed; prototype opaque (libnet80211). */
        ic_set_key(node->ifidx, 3, ks[185], node->mac, ks[186], ks + 168, kcfg);
    }
    return ESP_OK; /* a2 zeroed at +0x128, falls to retw */
}

/* mt_copy_peer @ manatick.o section+00000024 size 165B bind LOCAL
 * Calls: memset, memcpy (ASM_EXPAND, from disasm) | Data refs: g_mt, g_osi_funcs_p, wpa_crypto_funcs
 * Fidelity: high - field map (node+8/+9/+10/+16/+20 -> info+22/+24/+0/+32/+6), LMK open via wpa fn@20, fail-log-and-zero quirk exact. */
/* NOTE: not in funcdb (local); edges from disasm. */
static void mt_copy_peer(u8 *dst /* 36B public info */, const peer_node_t *src)
{
    u8 tmp[16];
    dst[22] = src->channel;                 /* +8 -> public channel+22 */
    dst[28] = (src->key != NULL) ? 1 : 0;   /* encrypt bool, movnez observed */
    *(u32 *)(dst + 24) = src->ifidx;        /* +9 -> public ifidx word+24 */
    memcpy(dst, src->mac /* +10 */, 6);
    if (src->key == NULL)
        goto out_priv;
    memset(tmp, 0, 16);
    {
        void *cf = wpa_crypto_funcs;
        void *open_fn = *(void **)((u8 *)cf + 20);
        if (open_fn == NULL)
            goto out_priv;
        memcpy(dst + 6 /* lmk */, (const u8 *)src->key + 168, 16);
        if (((int (*)(void *, void *, void *, u32))open_fn)(&g_mt, tmp, dst + 6, 16) == 0)
            goto out_priv;
        mt_log(1, "E (%d) %s: Decryption Failed", g_osi_funcs_p->_log_timestamp());
        memset(dst + 6, 0, 16);
    }
out_priv:
    *(void **)(dst + 32) = src->priv;       /* +16 -> public priv+32 */
}

/* mt_init @ manatick.o 00000040 size 178B bind GLOBAL
 * Calls: esp_wifi_internal_configure_wake_window, memset, pp_register_tx_cb, register_ieee80211_action_vendor_get_key_cb, register_ieee80211_action_vendor_spec_cb | Data refs: esp_wifi_internal_configure_wake_window, g_mt, g_mt_version, g_osi_funcs_p, memset, pp_register_tx_cb, register_ieee80211_action_vendor_get_key_cb, register_ieee80211_action_vendor_spec_cb
 * Fidelity: high - zero+square init, cb registrations, wake default, version log exact; vendor-cb return values unchecked in disasm (kept unchecked). */
int mt_init(void)
{
    int i;
    memset(&g_mt, 0, sizeof(g_mt)); /* 60 observed */
    for (i = 0; i < 16; i++)
        g_mt.key_state[i] = (u8)(i * i); /* mull+s8i loop observed */
    /* Outgoing (a10..a12): cb, 7, 0 observed. */
    if (pp_register_tx_cb(mt_send_cb, 7, 0) == 0)
        goto registered;
    mt_log(1, "E (%d) %s: Register send call back fail!",
           g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_INTERNAL;
registered:
    register_ieee80211_action_vendor_spec_cb(mt_recv_cb);
    register_ieee80211_action_vendor_get_key_cb(mt_get_lmk);
    g_mt.wake_window = 0xFFFF; /* s16i -1 at +56 observed */
    esp_wifi_internal_configure_wake_window(&g_mt.wake_window, 1);
    if (g_osi_funcs_p != NULL) {
        osi_t *osi = g_osi_funcs_p;
        if (osi->_log_write != NULL)
            osi->_log_write(3, TAG_ESPNOW, "I (%d) %s: espnow [version: %d.0] init",
                            osi->_log_timestamp(), TAG_ESPNOW, g_mt_version);
    }
    return ESP_OK;
}

/* mt_deinit @ manatick.o 00000040 size 389B bind GLOBAL
 * Calls: esp_wifi_internal_configure_wake_window, esp_wifi_internal_offchan_cancel, ieee80211_mt_key_is_mask_zero, pp_unregister_tx_cb, unregister_ieee80211_action_vendor_get_key_cb, unregister_ieee80211_action_vendor_spec_cb | Data refs: esp_wifi_internal_configure_wake_window, esp_wifi_internal_offchan_cancel, g_mt, g_mt_version, g_osi_funcs_p, ieee80211_mt_key_is_mask_zero, pp_unregister_tx_cb, unregister_ieee80211_action_vendor_get_key_cb, unregister_ieee80211_action_vendor_spec_cb
 * Fidelity: high - teardown order, node-walk frees, count asserts (log+"manatick.c"+line then self-loop hang) exact; mask-selector semantics opaque (libnet80211). */
static void mt_assert_hang(u32 line)
{
    osi_t *osi = g_osi_funcs_p;
    if (osi != NULL && osi->_log_write != NULL) {
        u32 t = osi->_log_timestamp();
        /* fmt "E (%d) %s: %s %d" with file on stack (s32i observed). */
        osi->_log_write(1, TAG_ESPNOW, "E (%d) %s: %s %d", t, TAG_ESPNOW, "manatick.c", line);
    }
    for (;;) {} /* disasm: j . self-loop */
}
int mt_deinit(void)
{
    peer_node_t *n;
    esp_wifi_internal_offchan_cancel(1); /* outgoing a10=1 observed */
    g_mt.recv_cb = NULL;  /* +48 */
    g_mt.send_cb = NULL;  /* +52 */
    unregister_ieee80211_action_vendor_spec_cb();
    pp_unregister_tx_cb(7); /* outgoing a10=7 observed */
    unregister_ieee80211_action_vendor_get_key_cb();
    esp_wifi_internal_configure_wake_window(&g_mt.wake_window, 0);
    while ((n = g_mt.head) != NULL) {
        g_mt.head = n->next;
        if (n->key != NULL) {
            mt_clear_lmk(n); /* LOCAL edge (+0x8 entry) */
            g_mt.enc_count--;
            g_osi_funcs_p->_free(n->key);
        }
        if (n->rate != NULL)
            g_osi_funcs_p->_free(n->rate);
        g_osi_funcs_p->_free(n);
        g_mt.total--;
    }
    if (g_mt.total != 0)
        mt_assert_hang(0x107);
    if (g_mt.enc_count != 0)
        mt_assert_hang(0x108);
    g_mt.cursor = NULL; /* +44 */
    g_mt.tail = NULL;   /* +32 */
    if (ieee80211_mt_key_is_mask_zero(0) != 0) /* outgoing a10=0 observed */
        mt_assert_hang(0x10c);
    if (ieee80211_mt_key_is_mask_zero(1) == 0) /* outgoing a10=1 observed */
        mt_assert_hang(0x10d);
    if (g_osi_funcs_p != NULL) {
        osi_t *osi = g_osi_funcs_p;
        if (osi->_log_write != NULL)
            osi->_log_write(3, TAG_ESPNOW, "I (%d) %s: espnow [version: %d.0] deinit",
                            osi->_log_timestamp(), TAG_ESPNOW, g_mt_version);
    }
    return ESP_OK;
}

/* mt_register_recv_cb @ manatick.o 00000014 size 57B bind GLOBAL
 * Calls: none | Data refs: g_mt, g_osi_funcs_p
 * Fidelity: high - NULL check + store, exact. */
int mt_register_recv_cb(void *cb)
{
    if (cb == NULL) {
        mt_log(1, "E (%d) %s: Recv call back is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_INTERNAL; /* literal +0 observed */
    }
    g_mt.recv_cb = cb; /* +48 */
    return ESP_OK;
}

/* mt_unregister_recv_cb @ manatick.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_mt
 * Fidelity: high - clears +48, returns void (no a2 set in disasm). */
void mt_unregister_recv_cb(void)
{
    g_mt.recv_cb = NULL; /* +48 */
}

/* mt_register_send_cb @ manatick.o 00000014 size 57B bind GLOBAL
 * Calls: none | Data refs: g_mt, g_osi_funcs_p
 * Fidelity: high - NULL check + store, exact. */
int mt_register_send_cb(void *cb)
{
    if (cb == NULL) {
        mt_log(1, "E (%d) %s: Send call back is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_INTERNAL; /* literal +0 observed */
    }
    g_mt.send_cb = cb; /* +52 */
    return ESP_OK;
}

/* mt_unregister_send_cb @ manatick.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_mt
 * Fidelity: high - clears +52, returns void (no a2 set in disasm). */
void mt_unregister_send_cb(void)
{
    g_mt.send_cb = NULL; /* +52 */
}

/* mt_send @ manatick.o 0000003c size 230B bind GLOBAL
 * Calls: ieee80211_send_action_vendor_spec, memcmp | Data refs: g_chm, g_mt, g_osi_funcs_p, ieee80211_send_action_vendor_spec, memcmp
 * Fidelity: high - validation, channel check, send-arg build, wifi->espnow error mapping (0x101->NO_MEM, 0x3004->IF, -1->INTERNAL) exact; arg#5 (send_cb?0:g_mt) kept as observed with comment. */
int mt_send(const u8 *peer_addr, const u8 *data, u32 len)
{
    peer_node_t *n;
    u32 home_ch;
    int ret;
    if (peer_addr == NULL || data == NULL)
        goto invalid;
    if (len == 0 || len > 1470) /* (len-1) > 0x5bd unsigned, observed */
        goto invalid;
    for (n = g_mt.head; n != NULL; n = n->next) {
        if (memcmp(n->mac /* +10 */, peer_addr, 6) == 0)
            goto found;
    }
    return ESP_ERR_ESPNOW_NOT_FOUND;
found:
    if (n->channel /* +8 */ != 0) {
        home_ch = *(u8 *)((u8 *)g_chm + 80); /* g_chm byte+80 observed */
        if (n->channel != (u8)home_ch) {
            mt_log(1, "E (%d) %s: Peer channel is not equal to the home channel, send fail!",
                   g_osi_funcs_p->_log_timestamp());
            return ESP_ERR_ESPNOW_CHAN; /* literal +0x4 (0x306d) observed */
        }
    }
    /* Outgoing (a10..a15): ifidx(+9), peer, data, len, x5, rate(+24). */
    ret = ieee80211_send_action_vendor_spec(n->ifidx, peer_addr, data, len,
            (g_mt.send_cb == NULL) ? (u32)&g_mt : 0, n->rate);
    if (ret == 0x101)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (ret == 0x3004)
        return ESP_ERR_ESPNOW_IF;
    if (ret != -1)
        return ret;
    return ESP_ERR_ESPNOW_INTERNAL;
invalid:
    mt_log(1, "E (%d) %s: Invalid argument!", g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_ARG;
}

/* mt_del_peer @ manatick.o 00000020 size 226B bind GLOBAL
 * Calls: memcmp (+ mt_clear_lmk via LOCAL edge, from disasm) | Data refs: g_mt, g_osi_funcs_p, memcmp
 * Fidelity: high - find/unlink (head/tail/cursor fixups), key+rate+node frees, count-- exact; funcdb lists only external memcmp (LOCAL edge kept). */
int mt_del_peer(const u8 *peer_addr)
{
    peer_node_t *n;
    if (peer_addr == NULL) {
        mt_log(1, "E (%d) %s: Peer address is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    for (n = g_mt.head /* +28 */; n != NULL; n = n->next) {
        if (memcmp(n->mac /* +10 */, peer_addr, 6) == 0)
            goto found;
    }
    return ESP_ERR_ESPNOW_NOT_FOUND;
found:
    /* Unlink with head/tail/prev/next fixups (all four bne topologies traced). */
    if (n->prev == NULL && n->next == NULL) {
        g_mt.head = NULL; g_mt.tail = NULL;         /* sole node */
    } else if (n->prev == NULL) {
        g_mt.head = n->next; n->next->prev = NULL;  /* remove head */
    } else if (n->next == NULL) {
        g_mt.tail = n->prev; n->prev->next = NULL;  /* remove tail */
    } else {
        n->prev->next = n->next; n->next->prev = n->prev; /* middle */
    }
    if (g_mt.cursor == n)
        g_mt.cursor = n->next; /* +44 fixup observed */
    if (n->key != NULL) {
        mt_clear_lmk(n);                            /* LOCAL edge */
        g_osi_funcs_p->_free(n->key);
        g_mt.enc_count--;                           /* +40 observed */
    }
    if (n->rate != NULL)
        g_osi_funcs_p->_free(n->rate);              /* +24 observed */
    g_osi_funcs_p->_free(n);
    g_mt.total--;                                   /* +36 observed */
    return ESP_OK;
}

/* mt_mod_peer @ manatick.o 00000044 size 364B bind GLOBAL
 * Calls: memcmp, memset (+ mt_get_key_idx/mt_clear_lmk/mt_set_lmk via LOCAL edges, from disasm) | Data refs: g_mt, g_osi_funcs_p, g_wifi_menuconfig, memcmp, memset
 * Fidelity: high - find, three encrypt transitions (drop/rekey/upgrade), field updates, FULL/NO_MEM/NOT_FOUND returns exact. mt_set_lmk mode arg: 0 = alloc slot (fresh struct: add/upgrade paths), 1 = reuse slot (rekey path; stale movi a12,1 at +0x92 traced). */
int mt_mod_peer(const u8 *info)
{
    peer_node_t *n;
    if (info == NULL) {
        mt_log(1, "E (%d) %s: Peer is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    for (n = g_mt.head; n != NULL; n = n->next) {
        if (memcmp(n->mac /* +10 */, info + 10, 6) == 0)
            goto found;
    }
    return ESP_ERR_ESPNOW_NOT_FOUND;
found:
    if (n->key == NULL) {
        /* Open peer: store ifidx/channel/priv; stay open or upgrade. */
        n->ifidx = *(const u32 *)(info + 24);       /* s8i low byte */
        n->channel = info[22];
        n->priv = *(void *const *)(info + 16);
        if (info[28] == 0)
            return ESP_OK;
        if (g_mt.enc_count >= *(const u32 *)(g_wifi_menuconfig + 80)) {
            mt_log(1, "E (%d) %s: Encrypt peer is full", g_osi_funcs_p->_log_timestamp());
            return ESP_ERR_ESPNOW_FULL;             /* 0x60d<<3 observed */
        }
        n->key = g_osi_funcs_p->_wifi_malloc(192);
        if (n->key == NULL) {
            mt_log(1, "E (%d) %s: malloc key fail", g_osi_funcs_p->_log_timestamp());
            return ESP_ERR_ESPNOW_NO_MEM;
        }
        memset(n->key, 0, 192);                     /* a11=a2=memcmp-zero traced */
        g_mt.enc_count++;
        /* mode=0 (a12 carries memcmp-zero via a2, traced): alloc slot. */
        return mt_set_lmk(n, info + 6, 0);          /* LOCAL edge */
    }
    /* Encrypted peer. */
    if (n->ifidx != (u8)*(const u32 *)(info + 24)) {
        /* Interface changed: require a free slot, drop old LMK, store new ifidx. */
        if (mt_get_key_idx() == 0xFFFF)             /* LOCAL edge */
            return ESP_ERR_ESPNOW_FULL;             /* no log observed here */
        mt_clear_lmk(n);                            /* LOCAL edge */
        n->ifidx = *(const u32 *)(info + 24);
    }
    n->channel = info[22];
    n->priv = *(void *const *)(info + 16);
    if (info[28] == 0) {
        /* Drop encryption. */
        mt_clear_lmk(n);                            /* LOCAL edge */
        g_osi_funcs_p->_free(n->key);
        n->key = NULL;
        g_mt.enc_count--;
        return ESP_OK; /* a2 = memcmp-zero carried to retw, traced */
    }
    /* Rekey in place (slot reused, mode=1). */
    return mt_set_lmk(n, info + 6, 1);              /* LOCAL edge */
}

/* mt_get_peer @ manatick.o 00000020 size 118B bind GLOBAL
 * Calls: memcmp (+ mt_copy_peer via LOCAL edge, from disasm) | Data refs: g_mt, g_osi_funcs_p, memcmp
 * Fidelity: high - NULL checks, MAC walk, copy-out exact. */
int mt_get_peer(const u8 *peer_addr, u8 *peer /* 36B public info */)
{
    peer_node_t *n;
    if (peer_addr == NULL || peer == NULL) {
        mt_log(1, "E (%d) %s: Peer address or peer is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    for (n = g_mt.head; n != NULL; n = n->next) {
        if (memcmp(n->mac, peer_addr, 6) == 0) {
            mt_copy_peer(peer, n);                  /* LOCAL edge */
            return ESP_OK;
        }
    }
    return ESP_ERR_ESPNOW_NOT_FOUND;
}

/* mt_get_peer_info @ manatick.o 00000014 size 84B bind GLOBAL
 * Calls: memcmp | Data refs: g_mt, g_osi_funcs_p, memcmp
 * Fidelity: high - returns internal node* (or NULL); NULL-mac logs, exact. */
peer_node_t *mt_get_peer_info(const u8 *peer_addr)
{
    peer_node_t *n;
    if (peer_addr == NULL) {
        /* Reuses del_peer string section (refs .rodata.mt_del_peer.str1.1). */
        mt_log(1, "E (%d) %s: Peer address is NULL", g_osi_funcs_p->_log_timestamp());
        return NULL;
    }
    for (n = g_mt.head; n != NULL; n = n->next) {
        if (memcmp(n->mac, peer_addr, 6) == 0)
            return n;
    }
    return NULL;
}

/* mt_fetch_peer @ manatick.o 0000001c size 129B bind GLOBAL
 * Calls: (none external; mt_copy_peer via LOCAL edge, from disasm) | Data refs: g_mt, g_osi_funcs_p
 * Fidelity: high - cursor walk skipping multicast (mac0&1), copy+advance exact; funcdb calls[] empty because the only call is LOCAL. */
int mt_fetch_peer(u8 from_head, u8 *peer /* 36B public info */)
{
    peer_node_t *n;
    int skipped;
    if (peer == NULL) {
        /* Reuses mod_peer string section (refs .rodata.mt_mod_peer.str1.1). */
        mt_log(1, "E (%d) %s: Peer is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    if (from_head)
        g_mt.cursor = g_mt.head; /* +44 reset observed */
    skipped = 0;
    for (n = g_mt.cursor; n != NULL; n = n->next) {
        if ((n->mac[0] & 1) == 0)
            goto copy; /* unicast: bbci bit0 observed */
        skipped = 1;
    }
    g_mt.cursor = NULL;
    return ESP_ERR_ESPNOW_NOT_FOUND;
copy:
    if (skipped)
        g_mt.cursor = n;
    mt_copy_peer(peer, n); /* LOCAL edge */
    g_mt.cursor = n->next; /* advance observed */
    return ESP_OK;
}

/* mt_is_peer_exist @ manatick.o 00000014 size 82B bind GLOBAL
 * Calls: memcmp | Data refs: g_mt, g_osi_funcs_p, memcmp
 * Fidelity: high - NULL-mac log + MAC walk returning 1/0, exact. */
int mt_is_peer_exist(const u8 *peer_addr)
{
    peer_node_t *n;
    if (peer_addr == NULL) {
        /* Reuses get_peer string section (refs .rodata.mt_get_peer.str1.1). */
        mt_log(1, "E (%d) %s: Peer address or peer is NULL", g_osi_funcs_p->_log_timestamp());
        return 0;
    }
    for (n = g_mt.head; n != NULL; n = n->next) {
        if (memcmp(n->mac, peer_addr, 6) == 0)
            return 1;
    }
    return 0;
}

/* mt_add_peer @ manatick.o 00000060 size 834B bind GLOBAL
 * Calls: ieee80211_regdomain_check_channel, memcpy, memset, mt_is_peer_exist (+ mt_set_lmk via LOCAL edge, from disasm) | Data refs: g_mt, g_osi_funcs_p, g_wifi_menuconfig, ieee80211_regdomain_check_channel, memcpy, memset, mt_is_peer_exist
 * Fidelity: high - validation chain (NULL/full/multicast/channel/ifidx/ exist), 28B node + 192B key allocs, field copy, set_lmk(mode 0), list-link with corrupt-list assert hangs (log+"manatick.c"+line then self-loop), count updates exact. */
int mt_add_peer(const u8 *info)
{
    peer_node_t *node;
    if (info == NULL) {
        /* Reuses mod_peer string section (refs .rodata.mt_mod_peer.str1.1). */
        mt_log(1, "E (%d) %s: Peer is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    if (g_mt.total >= 20) { /* movi 19 / bge observed (max 20 total) */
        mt_log(1, "E (%d) %s: Peer is full", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_FULL;
    }
    if ((info[0] & 1) != 0 && info[28] != 0) { /* bbci bit0 + encrypt flag */
        mt_log(1, "E (%d) %s: Do not support encryption for multicast address",
               g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    if (info[22] != 0) { /* channel word low byte; 0 = home channel */
        if (ieee80211_regdomain_check_channel(info[22]) == 0) {
            mt_log(1, "E (%d) %s: Peer channel is not support, need to change channel",
                   g_osi_funcs_p->_log_timestamp());
            return ESP_ERR_ESPNOW_ARG;
        }
    }
    if (*(const u32 *)(info + 24) >= 2) { /* bltui ifidx,2 observed */
        mt_log(1, "E (%d) %s: Peer interface is invalid", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    if (mt_is_peer_exist(info)) {
        /* WARN level 2 via shared j-target (5 log args, no extra). */
        mt_log(2, "W (%d) %s: Peer exists. Please call API esp_now_mod_peer()!",
               g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_EXIST;
    }
    node = g_osi_funcs_p->_wifi_malloc(28);
    if (node == NULL) {
        mt_log(1, "E (%d) %s: malloc peer fail", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_NO_MEM;
    }
    memset(node, 0, 28); /* fill = is_exist-zero carried in a6/a11, traced */
    if (info[28] != 0) {
        /* Encrypted: capacity vs menuconfig+80, 192B key struct, seal LMK. */
        if (g_mt.enc_count >= *(const u32 *)(g_wifi_menuconfig + 80)) {
            mt_log(1, "E (%d) %s: Encrypt peer is full", g_osi_funcs_p->_log_timestamp());
            g_osi_funcs_p->_free(node);
            return ESP_ERR_ESPNOW_FULL;
        }
        node->key = g_osi_funcs_p->_wifi_malloc(192);
        if (node->key == NULL) {
            mt_log(1, "E (%d) %s: malloc key fail", g_osi_funcs_p->_log_timestamp());
            g_osi_funcs_p->_free(node);
            return ESP_ERR_ESPNOW_NO_MEM;
        }
        memset(node->key, 0, 192);
    }
    /* Field copy (public info -> node). */
    node->channel = info[22];
    node->ifidx = (u8)*(const u32 *)(info + 24);
    node->priv = *(void *const *)(info + 16);
    memcpy(node->mac /* +10 */, info, 6);
    if (node->key != NULL) {
        /* mode=0 (movi a12,0 observed): alloc key slot + program. */
        if (mt_set_lmk(node, info + 6, 0) != 0) {   /* LOCAL edge */
            mt_log(1, "E (%d) %s: set lmk fail", g_osi_funcs_p->_log_timestamp());
            g_osi_funcs_p->_free(node->key);
            g_osi_funcs_p->_free(node);
            return ESP_ERR_ESPNOW_FULL; /* 0x60d<<3 observed (quirk: not NO_MEM) */
        }
    }
    /* Link with corrupt-list invariant asserts (hang on violation). */
    if (g_mt.head == NULL) {
        if (g_mt.tail != NULL)
            mt_assert_hang(0x1a7);
        if (g_mt.total != 0)
            mt_assert_hang(0x1a8);
        if (g_mt.enc_count != 0)
            mt_assert_hang(0x1a9);
        g_mt.head = node;
        g_mt.tail = node;
        node->next = NULL; /* a2 = enc-zero observed */
        node->prev = NULL;
    } else {
        if (g_mt.tail == NULL)
            mt_assert_hang(0x1af);
        g_mt.tail->next = node;
        node->prev = g_mt.tail;
        node->next = NULL;
        g_mt.tail = node;
    }
    g_mt.total++;
    if (node->key != NULL)
        g_mt.enc_count++;
    return ESP_OK;
}

/* mt_get_peer_num @ manatick.o 00000014 size 62B bind GLOBAL
 * Calls: none | Data refs: g_mt, g_osi_funcs_p
 * Fidelity: high - NULL check + total/enc copy-out, exact. */
int mt_get_peer_num(u32 *num /* [total, encrypt] */)
{
    if (num == NULL) {
        mt_log(1, "E (%d) %s: Number is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    num[0] = g_mt.total;      /* +36 */
    num[1] = g_mt.enc_count;  /* +40 */
    return ESP_OK;
}

/* mt_get_version @ manatick.o 00000014 size 58B bind GLOBAL
 * Calls: none | Data refs: g_mt_version, g_osi_funcs_p
 * Fidelity: high - NULL check + version copy-out, exact. */
int mt_get_version(u32 *version)
{
    if (version == NULL) {
        mt_log(1, "E (%d) %s: Version is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    *version = g_mt_version;
    return ESP_OK;
}

/* mt_set_pmk @ manatick.o 00000018 size 62B bind GLOBAL
 * Calls: memcpy | Data refs: g_mt, g_osi_funcs_p, memcpy
 * Fidelity: high - NULL check + 16B copy to g_mt+0 (rela addend confirms), exact. NOTE: overwrites the key_state[16] init pattern (see ledger). */
int mt_set_pmk(const u8 *pmk)
{
    if (pmk == NULL) {
        mt_log(1, "E (%d) %s: PMK is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    memcpy(g_mt.key_state /* +0, 16B */, pmk, 16);
    return ESP_OK;
}

/* mt_set_wake_window @ manatick.o 00000010 size 53B bind GLOBAL
 * Calls: esp_wifi_internal_configure_wake_window | Data refs: esp_wifi_internal_configure_wake_window, g_mt
 * Fidelity: high - change-detect + disable/store/conditional-enable exact. */
int mt_set_wake_window(u16 window)
{
    if (g_mt.wake_window /* +56 */ == window)
        return ESP_OK;
    esp_wifi_internal_configure_wake_window(&g_mt.wake_window, 0);
    g_mt.wake_window = window; /* s16i observed */
    if (window == 0)
        return ESP_OK;
    esp_wifi_internal_configure_wake_window(&g_mt.wake_window, 1);
    return ESP_OK;
}

/* mt_set_user_oui @ manatick.o 00000004 size 39B bind GLOBAL
 * Calls: none | Data refs: g_espnow_user_oui
 * Fidelity: high - NULL is a no-op success (beqz straight to return 0), else 3 byte stores, exact. */
int mt_set_user_oui(const u8 *oui)
{
    if (oui == NULL)
        return ESP_OK;
    g_espnow_user_oui[0] = oui[0];
    g_espnow_user_oui[1] = oui[1];
    g_espnow_user_oui[2] = oui[2];
    return ESP_OK;
}

/* mt_get_user_oui @ manatick.o 00000014 size 78B bind GLOBAL
 * Calls: none | Data refs: g_espnow_user_oui, g_osi_funcs_p
 * Fidelity: high - NULL check + 3 byte copy-out, exact. */
int mt_get_user_oui(u8 *oui)
{
    if (oui == NULL) {
        mt_log(1, "E (%d) %s: oui is NULL", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_ARG;
    }
    oui[0] = g_espnow_user_oui[0];
    oui[1] = g_espnow_user_oui[1];
    oui[2] = g_espnow_user_oui[2];
    return ESP_OK;
}

/* mt_set_peer_rate_config @ manatick.o 00000050 size 618B bind GLOBAL
 * Calls: chm_get_band_from_chan, chm_get_current_channel, memcmp, memcpy | Data refs: chm_get_band_from_chan, chm_get_current_channel, g_chm, g_ic, g_mt, g_osi_funcs_p, g_wifi_nvs, memcmp, memcpy
 * Fidelity: low - ladder interior (all branch constants/strings/returns exact, field semantics inferred); entries, store path, QUIRK return high. */
int mt_set_peer_rate_config(const u8 *peer, const u32 *config)
{
    u32 mode, rate;
    u8 ch;
    u32 ic_sel, band;
    u8 *rate12;
    peer_node_t *n;
    if (config == NULL || peer == NULL)
        return ESP_ERR_ESPNOW_ARG; /* moveqz/movnez+extui idiom observed */
    mode = config[0];
    if (mode == 0)
        goto store; /* beqz observed: mode 0 bypasses validation (LR path) */
    /* Capability select from peer word+24 (opaque ic cells +16/+20). */
    ic_sel = (((const u32 *)peer)[6] == 1)
        ? *(const u32 *)((const u8 *)g_ic + 20)
        : *(const u32 *)((const u8 *)g_ic + 16);
    if (ic_sel == 0)
        return ESP_ERR_ESPNOW_INTERNAL; /* literal +0x4 observed */
    ch = peer[22];
    if (ch == 0)
        ch = (u8)chm_get_current_channel();
    {
        const u8 *tab = (const u8 *)(ic_sel + 0x100); /* addmi observed */
        band = tab[104];                              /* l8ui observed */
        if (ch > 14) goto band_path2;
        if (band < 3 && mode >= 3)
            goto bad_phymode;
        if (((mode & ~4u) == 3u))
            goto bad_phymode;
        rate = config[4];
        if (mode < 3) { if (rate > 15) goto bad_rate; goto band_path; }   /* 0xbc */
        /* mode >= 3: inverted bound observed */
        if (rate > 15) goto band_path; else goto bad_rate;                /* 0xc5 */
band_path2: /* ch > 14 */
        if (band < 5) goto legacy_rate2;
        if (mode >= 3) goto legacy_rate2;
        goto bad_phymode; /* 0xf2 */
legacy_rate2:
        if (mode != 3) goto legacy_rate3;
        rate = config[4];
        if ((u32)(rate - 8) < 8) goto band_path; else goto bad_rate;      /* 0x100 */
legacy_rate3:
        if (mode < 4) goto band_path;                                     /* 0x104 */
        rate = config[4];
        if (rate > 15) goto band_path; else goto bad_rate;                /* 0x10e */
band_path:
        band = chm_get_band_from_chan(ch);
        band = ((const u8 *)(ic_sel + 0x100))[104];
        if (band != 3) goto mode5_path;
        if (mode < 6) goto mode5_path;
        goto bad_phymode;
mode5_path:
        if (mode != 5) goto mode6_path;
        /* Single dominating osi guard (disasm checks per log site; identical). */
        if (g_osi_funcs_p == NULL)
            return ESP_ERR_ESPNOW_ARG;
        {
            /* NVS capability byte selected by (band==1, peer-word==1). */
            u8 cap;
            u32 w24 = ((const u32 *)peer)[6]; /* +24 */
            if (band != 1) {
                cap = (w24 != 1) ? g_wifi_nvs[0x400 + 159] : g_wifi_nvs[0x500 + 54];
            } else {
                cap = (w24 != 1) ? g_wifi_nvs[157] : g_wifi_nvs[0x300 + 251];
            }
            if (cap != 2)
                goto bad_bw40;   /* +0x6c */
            if (g_wifi_nvs[81] == 0)
                goto bad_chan40; /* +0xa5 */
            goto store;
        }
mode6_path:
        if (mode != 6) goto store;
        {
            u32 r = config[4];
            const u8 *cb = (const u8 *)config;
            if (cb[8] == 0) {
                if ((u32)(r - 19) < 5u) goto bad_ersu;
                if (r > 26) goto bad_ersu;
                goto mcs_check; /* r<19 or 24..26 observed */
            }
mcs_check:
            if (cb[9] == 0) goto store;
            if (((r & ~8u) - 18u) == 0) goto bad_dcm;
            if ((u32)(r - 16) > 12u) goto bad_dcm;
            if ((u32)(r - 21) >= 3u) goto store;
            goto bad_dcm;
        }
    }
bad_phymode:
    mt_log(1, "E (%d) %s: invalid phymode, need to change phy mode",
           g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_ARG;
bad_rate:
    mt_log(1, "E (%d) %s: invalid rate, need change phy mode or rate",
           g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_ARG;
bad_bw40:
    mt_log(1, "E (%d) %s: invalid phymode, need change bandwidth to 40",
           g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_ARG;
bad_chan40:
    mt_log(1, "E (%d) %s: invalid chanel info, need change second channel to 40",
           g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_ARG;
bad_ersu:
    mt_log(1, "E (%d) %s: invalid rate, ersu only support mcs 0~2",
           g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_ARG;
bad_dcm:
    mt_log(1, "E (%d) %s: invalid rate, dcm only support mcs 0 1 3 4",
           g_osi_funcs_p->_log_timestamp());
    return ESP_ERR_ESPNOW_ARG;
store:
    rate12 = g_osi_funcs_p->_wifi_malloc(12);
    if (rate12 == NULL) {
        mt_log(1, "E (%d) %s: malloc peer fail", g_osi_funcs_p->_log_timestamp());
        return ESP_ERR_ESPNOW_NO_MEM;
    }
    memcpy(rate12, config, 12);
    for (n = g_mt.head; n != NULL; n = n->next) {
        if (memcmp(n->mac, peer, 6) == 0) {
            if (n->rate != NULL)
                g_osi_funcs_p->_free(n->rate);
            n->rate = rate12; /* +24 */
            /* QUIRK: a2=g_mt live at retw (traced); returns nonzero on success. */
            return (int)(uintptr_t)&g_mt;
        }
    }
    g_osi_funcs_p->_free(rate12);
    return ESP_ERR_ESPNOW_ARG;
}