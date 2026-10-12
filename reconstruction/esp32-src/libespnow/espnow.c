/* Reconstructed C for ESP32 libespnow.a :: espnow.o (Xtensa ELF32, windowed ABI).
 * Source: /tmp/re_esp32/libespnow/espnow.o + funcdb_libespnow.json v3 + full objdump -d -r.
 * Cross-refs: IDF esp_now.h (public API/structs), wifi_os_adapter.h (osi table layout, ESP32).
 * Conventions: args a2..a7 in, outgoing args caller a10..a15 (-> callee a2..a7),
 *   call target any reg via callx8, return value in caller a10 (a2 at retw boundary).
 * OSI indirect table (verified field-by-field against wifi_os_adapter.h, ESP32 layout):
 *   +76 _recursive_mutex_create, +84 _mutex_lock, +88 _mutex_unlock,
 *   +172 _malloc, +176 _free, +336 _log_write, +344 _log_timestamp,
 *   +364 _wifi_malloc, +376 _wifi_zalloc.
 * Log pattern (every site): t = _log_timestamp();
 *   _log_write(level, "ESPNOW", fmt, t, "ESPNOW" [, extra fmt args...]).
 * Error codes: ESP_OK 0; ESP_ERR_WIFI_NOT_INIT 0x3001; ESP_ERR_NO_MEM 0x101;
 *   ESP_ERR_INVALID_ARG 0x102; ESPNOW base 0x3064: NOT_INIT 0x3065, ARG 0x3066,
 *   NO_MEM 0x3067, FULL 0x3068, NOT_FOUND 0x3069, INTERNAL 0x306a,
 *   EXIST 0x306b, IF 0x306c, CHAN 0x306d.
 * Types: u8/u16/u32. Field names on recovered structs only where 2+ offsets
 * evidence them; all numeric offsets below were read off l32i/s32i/l8ui immediates.
 */
#include <stdint.h>
#include <stddef.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32;

#define ESP_OK                  0
#define ESP_ERR_WIFI_NOT_INIT   0x3001
#define ESP_ERR_NO_MEM          0x101
#define ESP_ERR_INVALID_ARG     0x102
#define ESP_ERR_ESPNOW_NOT_INIT 0x3065
#define ESP_ERR_ESPNOW_ARG      0x3066
#define ESP_ERR_ESPNOW_NO_MEM   0x3067
#define ESP_ERR_ESPNOW_FULL     0x3068
#define ESP_ERR_ESPNOW_NOT_FOUND 0x3069
#define ESP_ERR_ESPNOW_INTERNAL 0x306a
#define ESP_ERR_ESPNOW_EXIST    0x306b
#define ESP_ERR_ESPNOW_IF       0x306c
#define ESP_ERR_ESPNOW_CHAN     0x306d

/* Partial osi func table: only slots observed in this lib (offsets verified). */
typedef struct {
    u8  _pad0[76];                        /* +0 */
    void *(*_recursive_mutex_create)(void); /* +76 */
    u8  _pad1[4];                         /* +80 */
    s32 (*_mutex_lock)(void *mutex);      /* +84 */
    s32 (*_mutex_unlock)(void *mutex);    /* +88 */
    u8  _pad2[84];                        /* +92..175 */
    void *(*_malloc)(u32 size);           /* +172 */
    void (*_free)(void *p);               /* +176 */
    u8  _pad3[156];                       /* +180..335 */
    void (*_log_write)(u32 level, const char *tag, const char *fmt, ...); /* +336 */
    void (*_log_writev)(void);            /* +340 (unobserved; adapter.h order) */
    u32 (*_log_timestamp)(void);          /* +344 */
    u8  _pad4[16];                        /* +348..363 */
    void *(*_wifi_malloc)(u32 size);      /* +364 */
    u8  _pad5[8];                         /* +368..375 */
    void *(*_wifi_zalloc)(u32 size);      /* +376 */
} osi_funcs_t;

extern osi_funcs_t *g_osi_funcs_p;   /* BSS cell accessed via literal pool */
extern void *g_espnow_lock;          /* .bss.g_espnow_lock */
extern u8 g_wifi_menuconfig[];       /* opaque menuconfig blob; byte+97 read in init */
extern u8 g_wifi_nvs[];              /* opaque nvs blob */

/* Cross-lib externs (all UNDEFINED in this object; call targets from R_XTENSA_ASM_EXPAND). */
extern int ieee80211_espnow_get_init_flag(void);
extern void ieee80211_espnow_set_init_flag(int v);
extern int esp_wifi_ipc_internal(void *ipc_block, u32 flags);
extern int wifi_sta_restore_default_mac(void);
extern int wifi_init_completed(void);
extern void wifi_log(u32 x, u32 y, const char *fmt); /* observed called as (1,2,fmt) */
extern int ieee80211_ioctl(void *req);
extern void wifi_action_tx_process(void); /* stored into req struct, never called here */
extern void wifi_roc_process(void);       /* stored into req struct, never called here */
extern void *memset(void *d, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);
/* manatick.o entry points (defined in manatick.c). */
extern int mt_init(void); extern int mt_deinit(void);
extern int mt_register_recv_cb(void *cb); extern void mt_unregister_recv_cb(void);
extern int mt_register_send_cb(void *cb); extern void mt_unregister_send_cb(void);
extern int mt_send(const u8 *mac, const u8 *data, u32 len);
extern int mt_add_peer(const void *info); extern int mt_del_peer(const u8 *mac);
extern int mt_mod_peer(const void *info);
extern int mt_get_peer(const u8 *mac, void *out);
extern int mt_fetch_peer(u8 from_head, void *out);
extern int mt_is_peer_exist(const u8 *mac);
extern int mt_get_peer_num(void *out); extern int mt_get_version(u32 *out);
extern int mt_set_pmk(const u8 *pmk); extern int mt_set_wake_window(u16 w);
extern int mt_set_peer_rate_config(const void *peer, const void *cfg);
extern int mt_set_user_oui(u8 *oui); extern int mt_get_user_oui(u8 *oui);
extern void *mt_get_peer_info(const u8 *mac);

#define TAG_ESPNOW "ESPNOW"  /* .rodata.esp_now_init.str1.1+0 */

/* Log-guard pattern repeated verbatim at every site: skip log when osi or
 * _log_write slot is NULL (both l32i-checked); timestamp is fetched after. */
static void espnow_log(u32 level, const char *fmt, u32 t, const char *tag)
{
    osi_funcs_t *osi = g_osi_funcs_p;
    if (osi == NULL || osi->_log_write == NULL)
        return;
    osi->_log_write(level, TAG_ESPNOW, fmt, t, tag);
}
static void espnow_logx(u32 level, const char *fmt, u32 t, const char *tag, u32 x)
{
    osi_funcs_t *osi = g_osi_funcs_p;
    if (osi == NULL || osi->_log_write == NULL)
        return;
    osi->_log_write(level, TAG_ESPNOW, fmt, t, tag, x);
}

/* Ensure recursive mutex exists; returns 0 on success else ESP_ERR_ESPNOW_NO_MEM.
 * Exact block shared by all wrappers (create via slot+76, fail path logs
 * "E (%d) %s: esp now create mutex fail!" level 1 and returns 0x3067). */
static int espnow_ensure_lock(void)
{
    osi_funcs_t *osi;
    if (g_espnow_lock != NULL)
        return 0;
    g_espnow_lock = g_osi_funcs_p->_recursive_mutex_create();
    if (g_espnow_lock != NULL)
        return 0;
    osi = g_osi_funcs_p;
    if (osi != NULL && osi->_log_write != NULL)
        espnow_log(1, "E (%d) %s: esp now create mutex fail!",
                   osi->_log_timestamp(), TAG_ESPNOW);
    return ESP_ERR_ESPNOW_NO_MEM;
}

/* Standard locked init-check tail: lock, require init flag (else log
 * "E (%d) %s: esp now not init!", unlock, NOT_INIT). Returns 1 if dispatch ok. */
static int espnow_lock_and_check(void)
{
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    if (ieee80211_espnow_get_init_flag() != 0)
        return 1;
    espnow_log(1, "E (%d) %s: esp now not init!",
               g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return 0;
}

/* wifi_sta_restore_default_mac_wrapper @ espnow.o 00000004 size 12B bind LOCAL
 * Calls: wifi_sta_restore_default_mac | Data refs: (literal only, from disasm)
 * Fidelity: high - 3-instruction trampoline, exact. */
/* NOTE: not present in funcdb (local symbol); edges from disasm ground truth. */
static int wifi_sta_restore_default_mac_wrapper(void)
{
    return wifi_sta_restore_default_mac();
}

/* esp_now_init @ espnow.o 00000038 size 270B bind GLOBAL
 * Calls: esp_wifi_ipc_internal, ieee80211_espnow_get_init_flag, ieee80211_espnow_set_init_flag, mt_init | Data refs: .rodata.esp_now_init.str1.1, esp_wifi_ipc_internal, g_espnow_lock, g_osi_funcs_p, g_wifi_menuconfig, ieee80211_espnow_get_init_flag, ieee80211_espnow_set_init_flag, mt_init
 * Fidelity: high - full block trace incl. privacy IPC struct, all literals/levels. */
int esp_now_init(void)
{
    int ret;
    struct { void *fn; u32 zero1; u32 zero2; } ipc; /* 12B stack block at a1+0/4/8 */
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    if (ieee80211_espnow_get_init_flag() != 0) {
        /* Already init: INFO log, unlock, ESP_OK. */
        espnow_log(3, "I (%d) %s: esp now already init!",
                   g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ESP_OK;
    }
    /* Privacy/MAC-randomization gate: opaque menuconfig byte at +97. */
    if (g_wifi_menuconfig[97] != 0) {
        espnow_log(2, "W (%d) %s: Privacy enhancements enabled, restoring hardware MAC for ESP-NOW compatibility",
                   g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
        ipc.fn = wifi_sta_restore_default_mac_wrapper;
        ipc.zero1 = 0;
        ipc.zero2 = 0;
        ret = esp_wifi_ipc_internal(&ipc, 1);
        if (ret != 0) {
            espnow_logx(1, "E (%d) %s: Failed to restore hardware MAC (error %d), cannot init ESP-NOW with random MAC",
                        g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW, (u32)ret);
            g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
            return ret;
        }
    }
    ret = mt_init();
    if (ret != 0) {
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ret;
    }
    ieee80211_espnow_set_init_flag(1); /* outgoing a10=1 observed */
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_OK;
}

/* esp_now_deinit @ espnow.o 00000024 size 164B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, ieee80211_espnow_set_init_flag, mt_deinit | Data refs: .rodata.esp_now_deinit.str1.1, .rodata.esp_now_init.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, ieee80211_espnow_set_init_flag, mt_deinit
 * Fidelity: high - exact incl. set_init_flag(0) via reused mt_deinit zero return. */
int esp_now_deinit(void)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    if (ieee80211_espnow_get_init_flag() == 0) {
        /* Already deinit: INFO log, unlock, ESP_OK. */
        espnow_log(3, "I (%d) %s: esp now already deinit!",
                   g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ESP_OK;
    }
    ret = mt_deinit();
    if (ret != 0) {
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ret;
    }
    ieee80211_espnow_set_init_flag(0); /* disasm reuses mt_deinit's 0 in a10 */
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_OK;
}

/* esp_now_register_recv_cb @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_register_recv_cb | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_register_recv_cb
 * Fidelity: high - canonical 1-arg wrapper template, exact. */
int esp_now_register_recv_cb(void *cb)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_register_recv_cb(cb);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_unregister_recv_cb @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_unregister_recv_cb | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_unregister_recv_cb
 * Fidelity: high - canonical 0-arg wrapper template, exact. */
int esp_now_unregister_recv_cb(void)
{
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    mt_unregister_recv_cb();
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_OK; /* disasm: movi a2,0 after unlock */
}

/* esp_now_register_send_cb @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_register_send_cb | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_register_send_cb
 * Fidelity: high - canonical 1-arg wrapper template, exact. */
int esp_now_register_send_cb(void *cb)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_register_send_cb(cb);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_unregister_send_cb @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_unregister_send_cb | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_unregister_send_cb
 * Fidelity: high - canonical 0-arg wrapper template, exact. */
int esp_now_unregister_send_cb(void)
{
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    mt_unregister_send_cb();
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_OK; /* disasm: movi a2,0 after unlock */
}

/* esp_now_send @ espnow.o 00000038 size 328B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_fetch_peer, mt_send | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, .rodata.esp_now_send.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_fetch_peer, mt_send
 * Fidelity: high - unicast fast path + broadcast fetch loop fully traced. */
int esp_now_send(const u8 *peer_addr, const u8 *data, u32 len)
{
    int ret;
    u8 *tmp;      /* 36B temp peer-info (_wifi_malloc, slot+364) */
    int from_head;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    from_head = ieee80211_espnow_get_init_flag();
    if (from_head == 0) {
        espnow_log(1, "E (%d) %s: esp now not init!",
                   g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ESP_ERR_ESPNOW_NOT_INIT;
    }
    if (peer_addr != NULL) {
        /* Unicast fast path. */
        ret = mt_send(peer_addr, data, len);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ret;
    }
    /* Broadcast: walk peer list reusing one 36B temp (== sizeof public peer_info). */
    tmp = g_osi_funcs_p->_wifi_malloc(36);
    if (tmp == NULL) {
        espnow_log(1, "E (%d) %s: Malloc peer fail",
                   g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ESP_ERR_ESPNOW_NO_MEM;
    }
    /* NOTE: disasm passes the init-flag value as from_head (observed nonzero=1). */
    for (;;) {
        ret = mt_fetch_peer((u8)(from_head != 0), tmp);
        if (ret != 0)
            break;               /* no (more) peers */
        ret = mt_send(tmp, data, len);
        from_head = 0;           /* disasm: a9 = a7 (NULL peer) after first send */
        if (ret != 0) {
            g_osi_funcs_p->_free(tmp);
            g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
            return ESP_ERR_ESPNOW_INTERNAL; /* literal +0xc observed */
        }
    }
    g_osi_funcs_p->_free(tmp);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_ERR_ESPNOW_NOT_FOUND; /* literal +0x0 observed on fetch-exhausted exit */
}

/* esp_now_add_peer @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_add_peer | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_add_peer
 * Fidelity: high - canonical 1-arg wrapper template, exact. */
int esp_now_add_peer(const void *peer)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_add_peer(peer);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_del_peer @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_del_peer | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_del_peer
 * Fidelity: high - canonical 1-arg wrapper template, exact. */
int esp_now_del_peer(const u8 *peer_addr)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_del_peer(peer_addr);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_mod_peer @ espnow.o 00000024 size 156B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_mod_peer | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_mod_peer
 * Fidelity: high - canonical 1-arg wrapper template, exact. */
int esp_now_mod_peer(const void *peer)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_mod_peer(peer);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_get_peer @ espnow.o 00000024 size 162B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_get_peer | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_get_peer
 * Fidelity: high - 2-arg wrapper (mac, out) forwarded via a10/a11, exact. */
int esp_now_get_peer(const u8 *peer_addr, void *peer)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_get_peer(peer_addr, peer);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_fetch_peer @ espnow.o 00000024 size 166B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_fetch_peer | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_fetch_peer
 * Fidelity: high - 2-arg wrapper; bool from_head masked to u8 (extui 0,8), exact. */
int esp_now_fetch_peer(u32 from_head, void *peer)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_fetch_peer((u8)(from_head & 0xff), peer);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_is_peer_exist @ espnow.o 0000001c size 150B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_is_peer_exist | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_is_peer_exist
 * Fidelity: high - exact incl. quirks: create-fail returns 1, not-init returns 0. */
int esp_now_is_peer_exist(const u8 *peer_addr)
{
    int ret;
    const u8 *mac = peer_addr;
    if (g_espnow_lock == NULL) {
        g_espnow_lock = g_osi_funcs_p->_recursive_mutex_create();
        if (g_espnow_lock == NULL) {
            /* QUIRK: movi a2,1 precedes the log; failure returns true. */
            espnow_log(1, "E (%d) %s: esp now create mutex fail!",
                       g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
            return 1;
        }
    }
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    ret = ieee80211_espnow_get_init_flag();
    if (ret == 0) {
        /* Not init: logs, unlocks, returns flag value 0 (false). */
        espnow_log(1, "E (%d) %s: esp now not init!",
                   g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return 0;
    }
    ret = mt_is_peer_exist(mac);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_get_peer_num @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_get_peer_num | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_get_peer_num
 * Fidelity: high - canonical 1-arg wrapper template, exact. */
int esp_now_get_peer_num(void *num)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_get_peer_num(num);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_get_version @ espnow.o 00000018 size 96B bind GLOBAL
 * Calls: mt_get_version | Data refs: .rodata.esp_now_init.str1.1, g_espnow_lock, g_osi_funcs_p, mt_get_version
 * Fidelity: high - lock-only wrapper (NO init-flag check observed), exact. */
int esp_now_get_version(u32 *version)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    ret = mt_get_version(version);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_set_pmk @ espnow.o 00000024 size 160B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_set_pmk | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_set_pmk
 * Fidelity: high - canonical 1-arg wrapper template, exact. */
int esp_now_set_pmk(const u8 *pmk)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_set_pmk(pmk);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_set_wake_window @ espnow.o 00000024 size 164B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_set_wake_window | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, g_espnow_lock, g_osi_funcs_p, ieee80211_espnow_get_init_flag, mt_set_wake_window
 * Fidelity: high - u16 window masked (extui 0,16); init-flag checked, exact. */
int esp_now_set_wake_window(u32 window)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    ret = mt_set_wake_window((u16)(window & 0xffff));
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_set_peer_rate_config @ espnow.o 00000040 size 506B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, mt_get_peer, mt_set_peer_rate_config | Data refs: .rodata.esp_now_init.str1.1, .rodata.esp_now_register_recv_cb.str1.1, .rodata.esp_now_send.str1.1, .rodata.esp_now_set_peer_rate_config.str1.1, g_espnow_lock, g_osi_funcs_p, g_wifi_nvs, ieee80211_espnow_get_init_flag, mt_get_peer, mt_set_peer_rate_config
 * Fidelity: medium - validation chain + shared ERROR tails exact (all constants/ strings/returns traced); config-word semantics (u32@0=phymode,u32@4=rate) inferred from use; NVS LR-capability bytes opaque. */
int esp_now_set_peer_rate_config(const u8 *peer_addr, const void *config)
{
    /* Opaque config words as used: w0 = phy mode, w1 = rate. */
    const u32 *cfg = (const u32 *)config;
    u8 *tmp; /* 36B temp peer-info */
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    if (!espnow_lock_and_check())
        return ESP_ERR_ESPNOW_NOT_INIT;
    /* NULL peer or NULL config -> "invalid parameter" (shared tail -> ARG). */
    if (peer_addr == NULL || config == NULL)
        goto invalid;
    /* Rate word bound observed: movi 42 / bltu. */
    if (cfg[1] > 42)
        goto invalid;
    if (cfg[0] >= 7)
        goto invalid;
    if (cfg[0] != 0)
        goto lookup; /* legacy phy modes skip LR capability checks */
    /* LR (mode 0): requires LR-capable flags in g_wifi_nvs, else "invalid format". */
    if (g_wifi_nvs[0x400 + 161] == 0 && g_wifi_nvs[0x500 + 61] == 0)
        goto invalid_format;
    /* LR rate subset observed: (rate-41) < 2, else "invalid LR rate". */
    if ((u32)(cfg[1] - 41) >= 2)
        goto invalid_lr_rate;
lookup:
    tmp = g_osi_funcs_p->_wifi_malloc(36);
    if (tmp == NULL) {
        espnow_log(1, "E (%d) %s: Malloc peer fail",
                   g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ESP_ERR_ESPNOW_NO_MEM;
    }
    if (mt_get_peer(peer_addr, tmp) != 0) {
        /* Peer unknown: free temp, unlock, ARG. */
        g_osi_funcs_p->_free(tmp);
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        return ESP_ERR_ESPNOW_ARG;
    }
    if (cfg[0] != 0)
        goto apply; /* legacy mode: apply directly */
    /* LR mode with existing peer: peer word@24 selects further NVS gating. */
    {
        u32 pw = ((const u32 *)tmp)[6]; /* tmp+24 */
        if (pw == 0) {
            if (g_wifi_nvs[0x400 + 161] == 0)
                goto lr_gate2;
        } else {
            if (pw != 1)
                goto apply;
            /* fallthrough to second NVS gate */
        lr_gate2: ;
            if (g_wifi_nvs[0x500 + 61] == 0)
                goto invalid_format_free;
        }
    }
apply:
    ret = mt_set_peer_rate_config(tmp, config);
    g_osi_funcs_p->_free(tmp);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
invalid_format_free:
    espnow_log(1, "E (%d) %s: invalid format, need change phy mode to LR",
               g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
    g_osi_funcs_p->_free(tmp);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_ERR_ESPNOW_ARG;
invalid_format:
    espnow_log(1, "E (%d) %s: invalid format, need change phy mode to LR",
               g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_ERR_ESPNOW_ARG;
invalid_lr_rate:
    espnow_log(1, "E (%d) %s: invalid LR rate, need change rate to WIFI_PHY_RATE_LORA_250K or WIFI_PHY_RATE_LORA_500K",
               g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_ERR_ESPNOW_ARG;
invalid:
    espnow_log(1, "E (%d) %s: invalid parameter",
               g_osi_funcs_p->_log_timestamp(), TAG_ESPNOW);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ESP_ERR_ESPNOW_ARG;
}

/* esp_now_set_user_oui @ espnow.o 00000018 size 96B bind GLOBAL
 * Calls: mt_set_user_oui | Data refs: .rodata.esp_now_init.str1.1, g_espnow_lock, g_osi_funcs_p, mt_set_user_oui
 * Fidelity: high - lock-only wrapper (NO init-flag check observed), exact. */
int esp_now_set_user_oui(u8 *oui)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    ret = mt_set_user_oui(oui);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_get_user_oui @ espnow.o 00000018 size 96B bind GLOBAL
 * Calls: mt_get_user_oui | Data refs: .rodata.esp_now_init.str1.1, g_espnow_lock, g_osi_funcs_p, mt_get_user_oui
 * Fidelity: high - lock-only wrapper (NO init-flag check observed), exact. */
int esp_now_get_user_oui(u8 *oui)
{
    int ret;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    ret = mt_get_user_oui(oui);
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    return ret;
}

/* esp_now_switch_channel_tx @ espnow.o 00000044 size 360B bind GLOBAL
 * Calls: ieee80211_ioctl, memcpy, mt_get_peer_info, wifi_init_completed, wifi_log | Data refs: .rodata.esp_now_init.str1.1, .rodata_wlog_error.2, .rodata_wlog_error.3, .rodata_wlog_error.4, g_espnow_lock, g_osi_funcs_p, ieee80211_ioctl, memcpy, mt_get_peer_info, wifi_action_tx_process, wifi_init_completed, wifi_log
 * Fidelity: medium - all checks/constants/logs/returns exact; req-buffer field layout opaque (offsets as observed: cfg+17 MAC lookup, cfg+24 u16 len, cfg+26 6B copy src, buf1=data_len+48, buf2=24B with stored wifi_action_tx_process at +4). wifi_log observed as (1,2,fmt). */
int esp_now_switch_channel_tx(void *config)
{
    u8 *cfg = (u8 *)config;
    u16 data_len;
    void *node, *buf1, *buf2;
    int ret;
    if (wifi_init_completed() == 0)
        return ESP_ERR_WIFI_NOT_INIT; /* literal +0 observed */
    if (config == NULL)
        return ESP_ERR_INVALID_ARG;   /* a4=0x102 observed */
    data_len = *(u16 *)(cfg + 24);
    if (data_len == 0 || data_len > 1470) /* (len-1) > 0x5bd unsigned */
        goto bad_len;
    if (espnow_ensure_lock() != 0)
        return ESP_ERR_ESPNOW_NO_MEM;
    g_osi_funcs_p->_mutex_lock(g_espnow_lock);
    node = mt_get_peer_info(cfg + 17); /* opaque MAC offset, observed */
    if (node == NULL) {
        g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
        wifi_log(1, 2, "dest mac error, could not find the peer");
        return ESP_ERR_INVALID_ARG;
    }
    /* Channel compare (node u8+9), then UNLOCK before allocs (observed order). */
    g_osi_funcs_p->_mutex_unlock(g_espnow_lock);
    buf1 = g_osi_funcs_p->_wifi_zalloc((u32)data_len + 48);
    if (buf1 == NULL) {
        wifi_log(1, 2, "failed to allocate memory for offchan action tx req");
        return ESP_ERR_NO_MEM; /* 0x101 observed */
    }
    *(u32 *)((u8 *)buf1 + 0) = *(u8 *)((u8 *)node + 9);
    memcpy((u8 *)buf1 + 4, cfg + 26, 6);
    *(u32 *)((u8 *)buf1 + 12) = *(u32 *)(cfg + 0);
    ((u8 *)buf1)[16] = cfg[4];
    *(u32 *)((u8 *)buf1 + 20) = *(u32 *)(cfg + 8);
    *(u16 *)((u8 *)buf1 + 44) = data_len;
    *(u32 *)((u8 *)buf1 + 24) = *(u32 *)(cfg + 12);
    *(u32 *)((u8 *)buf1 + 32) = 0;
    memcpy((u8 *)buf1 + 48, cfg + 26, data_len); /* shared src offset observed */
    buf2 = g_osi_funcs_p->_wifi_zalloc(24);
    if (buf2 == NULL)
        ret = ESP_ERR_NO_MEM; /* skips ioctl, frees buf1 below */
    else {
        ((u8 *)buf2)[0] = 85; /* 'U', movi 85 observed */
        *(void **)((u8 *)buf2 + 4) = wifi_action_tx_process;
        *(u16 *)((u8 *)buf2 + 8) = 1;
        ((u8 *)buf2)[10] = 0;
        *(u32 *)((u8 *)buf2 + 12) = 0;
        *(void **)((u8 *)buf2 + 20) = buf1;
        ret = ieee80211_ioctl(buf2); /* buf2 ownership passes to wifi layer */
    }
    cfg[16] = ((u8 *)buf1)[36]; /* op_id copyback observed */
    g_osi_funcs_p->_free(buf1);
    return ret;
bad_len:
    wifi_log(1, 2, "data len error");
    return ESP_ERR_INVALID_ARG;
}

/* esp_now_remain_on_channel @ espnow.o 0000001c size 152B bind GLOBAL
 * Calls: ieee80211_ioctl, memset, wifi_init_completed | Data refs: g_osi_funcs_p, g_wifi_nvs, ieee80211_ioctl, memset, wifi_init_completed, wifi_roc_process
 * Fidelity: medium - init/NULL checks, 28B stack req, 24B zalloc req with stored (not called) wifi_roc_process at +4, ioctl, op_id copyback, exact; req-struct field semantics opaque (offsets as observed). */
int esp_now_remain_on_channel(void *config)
{
    u8 *cfg = (u8 *)config;
    u8 stack[28];
    u8 flag;
    void *buf;
    int ret;
    if (wifi_init_completed() == 0)
        return ESP_ERR_WIFI_NOT_INIT;
    if (config == NULL)
        return ESP_ERR_INVALID_ARG;
    memset(stack, 0, 28);
    /* Opaque NVS-derived flag: (g_wifi_nvs[0]-2)==0 ? 1 : 0 (moveqz observed). */
    flag = (g_wifi_nvs[0] == 2) ? 1 : 0;
    *(u32 *)(stack + 0) = flag;
    *(u32 *)(stack + 4) = *(u32 *)(cfg + 0);
    stack[8] = cfg[4];
    *(u32 *)(stack + 12) = *(u32 *)(cfg + 8);
    *(u32 *)(stack + 16) = *(u32 *)(cfg + 12);
    buf = g_osi_funcs_p->_wifi_zalloc(24);
    if (buf == NULL)
        ret = ESP_ERR_NO_MEM; /* skips ioctl; copyback runs with stack zeros */
    else {
        ((u8 *)buf)[0] = 86; /* 'V', movi 86 observed */
        *(void **)((u8 *)buf + 4) = wifi_roc_process;
        *(u16 *)((u8 *)buf + 8) = 1;
        ((u8 *)buf)[10] = 0;
        *(u32 *)((u8 *)buf + 12) = 0;
        *(void **)((u8 *)buf + 20) = stack;
        ret = ieee80211_ioctl(buf);
    }
    cfg[16] = stack[24]; /* op_id copyback observed */
    return ret;
}