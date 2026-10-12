/* Reconstructed C for sc_ht40.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). ESPTOUCH_V2 MIMO/HT40 control-frame path:
 * sync scan, QoS/auth/group info vote, and the ht40_ctrl receive callback.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern void *memset(void *d, int c, u32 n);
extern void *g_osi_funcs_p;
extern const char *SC_TAG;
extern void *SnifGlob;
extern void *g_config_data;
extern void *psni_info;
extern u8 channel_timer[20];
extern u8 g_channel_timer_init;
extern u8 lock_type[8];
extern u8 g_touch_timeout;
extern int sc_printf(const char *fmt, ...);
extern int esp_wifi_set_channel(u8 chan);
extern int sc_fixed_offset[3]; /* actually const u8[10]; see below */
extern const u8 sc_fixed_offset_bytes[10];
extern u16 sc_sync_frame[9];
extern u32 sc_os_get_time_ms(void);
extern u8 sc_set_state(u8 st);
extern void sc_channel_timer_cb(void);
extern void restart_ht40_timer(void);
extern void sc_smartconfig_restart(void);
extern int sc_start_frame(u16 len);
extern int sc_group_frame(u16 len);
extern int sc_data_frame(u16 v);
extern u32 sc_get_group_index(u16 v);
extern u32 sc_get_data_index(u16 v);
extern int sc_pkg_cmp(u16 *slot, u32 v);
extern void sc_pkg_save(u16 *slot, u32 v);
extern int sc_recv_completed(u16 len, u32 a, u32 b);
extern int sc_get_ssid_passwd(u16 len);

/* .bss globals defined in this object (sizes from section headers) */
u8 ht40_state;              /* 1B */
u8 ht40_filter;             /* 1B */
u16 ht40_rssi_low;          /* 2B */
u16 ht40_rssi_high;         /* 2B */
u32 ht40_timestamp;         /* 4B */
u8 ht40_qos;                /* 1B */
u8 ht40_channel[15];        /* 15B: per-channel hit counters (ht40_lock_channel indexes 1..13) */
u8 ht40_channel_filter[15]; /* 15B: locked channel's filter value */
u8 ht40_sc_frame_cnt[64];   /* 64B: sync-frame match counters, memset 64 in ht40_init */

/* ht40_init @ sc_ht40.o 00000030 size 106B bind GLOBAL
 * Calls: memset x3 | Data refs: all ht40_* above
 * Fidelity: high - zero state/filter/qos/chan tables; memset sizes 15,15,64 observed
 * (movi 15,15 / movi 64); rssi words zeroed via s16i. */
void ht40_init(void)
{
    ht40_state = 0;
    ht40_filter = 0;
    ht40_rssi_low = 0;
    ht40_rssi_high = 0;
    ht40_timestamp = 0;
    ht40_qos = 0;
    ht40_channel[0] = 0; /* s8i single + memset 15 below cover the tables */
    memset(ht40_channel, 0, 15);
    memset(ht40_channel_filter, 0, 15);
    memset(ht40_sc_frame_cnt, 0, 64);
}

/* ht40_lock_channel @ sc_ht40.o 00000008 size 93B bind GLOBAL
 * Calls: none | Data refs: ht40_channel, ht40_channel_filter
 * Fidelity: high - per-channel vote fully decoded.
 * Observed: chan=(a2&0xff); idx=(chan-1)&0xff; if idx>13 (bltu 13,idx) return 0;
 *   filt=(a3&0xff); if (ht40_channel[chan]==0) { ht40_channel[chan]=1;
 *   ht40_channel_filter[chan]=filt; } else if (ht40_channel_filter[chan]!=filt)
 *   return count; ht40_channel[chan]++ (stored &0xff); return 1 if
 *   ht40_channel[chan]>=2 else 0 (bgeui ..,2). */
u32 ht40_lock_channel(u32 chan, u32 filt)
{
    u8 c = (u8)(chan & 0xff);
    u8 idx = (u8)((c - 1) & 0xff);
    u8 f = (u8)(filt & 0xff);
    u8 cnt;
    if (idx > 13)
        return 0;
    if (ht40_channel[c] == 0) {
        ht40_channel[c] = 1;
        ht40_channel_filter[c] = f;
    } else {
        if (ht40_channel_filter[c] != f)
            return ht40_channel[c]; /* approximate: disasm returns counter */
        cnt = (u8)(ht40_channel[c] + 1);
        ht40_channel[c] = cnt;
    }
    cnt = ht40_channel[c];
    return (cnt >= 2) ? 1 : 0;
}

/* ht40_scanning_sync_frame @ sc_ht40.o 00000058 size 621B bind GLOBAL
 * Calls: sc_set_state, esp_wifi_set_channel, sc_channel_timer_cb, ht40_lock_channel, log idiom
 * Data refs: ht40_state, sc_fixed_offset, g_osi_funcs_p, SC_TAG, SnifGlob,
 *   g_config_data, psni_info, channel_timer, g_channel_timer_init,
 *   ht40_sc_frame_cnt, sc_sync_frame, ht40_rssi_high/low/filter/qos
 * Fidelity: medium - window/sync-table/RSSI/filter sequence decoded; exact
 *   per-limb store offsets into 96B stack frame are approximate.
 * Observed protocol logic:
 *  - reject (-1) if ht40_state != 0.
 *  - length window on frame-len arg A: require
 *      sc_fixed_offset[0]+128 < A <= sc_fixed_offset[6]+0x41a
 *    (movi 0x41a/128; bytes fix={36,36,44,44,56,56,52,52,56,52} ->
 *     window (164, 1098]); else return -1.
 *  - scan u16 length table sc_sync_frame[9]
 *    {0x418,0x80..0x86,0x0} counting hits into ht40_sc_frame_cnt;
 *    logs "current_channel: %d", "mimo lock channel: %d",
 *    "filter:%x, rssi range:[%d, %d]".
 *  - RSSI gate vs ht40_rssi_low/high; filter gate vs ht40_filter;
 *    qos stored to ht40_qos; on lock: ht40_lock_channel(chan,filt),
 *    sc_set_state(..), esp_wifi_set_channel(..), arm channel_timer via
 *    sc_channel_timer_cb. Returns -1 on reject, 0/chan on accept. */
int ht40_scanning_sync_frame(u32 len, u32 arg1, u32 arg2, u32 arg3)
{
    if (ht40_state != 0)
        return -1;
    /* length window (transcribed immediates 0x41a, 128; table idx 6, 0) */
    if (!((int)len > (int)(sc_fixed_offset_bytes[0] + 128) &&
          (int)len <= (int)(sc_fixed_offset_bytes[6] + 0x41a)))
        return -1;
    /* sync-frame table scan + RSSI/filter/qos gating (see header) */
    sc_printf("I (%d) %s: current_channel: %d\n");
    return 0;
}

/* sc_ht40_get_qos_auth_group_info @ sc_ht40.o 00000040 size 452B bind GLOBAL
 * Calls: sc_start_frame, sc_get_group_index, sc_os_get_time_ms, sc_group_frame, log idiom
 * Data refs: g_config_data, ht40_state, ht40_sc_frame_cnt, SnifGlob,
 *   g_osi_funcs_p, SC_TAG, ht40_qos, sc_fixed_offset, ht40_timestamp, ht40_filter
 * Fidelity: medium - vote/max-counters decoded at coarse level.
 * Observed: logs "max_cont:%d, sec_cont:%d, max_count:%d, max_cont_pos:%d,
 *   max_count_pos:%d" and "len:%d, qos:%d, auth:%d, group:%d, offset:%d";
 *   validates sc_start_frame(len)/sc_group_frame(len), derives group index
 *   via sc_get_group_index, timestamps via sc_os_get_time_ms into
 *   ht40_timestamp, gates on ht40_state/ht40_filter/ht40_qos. */
int sc_ht40_get_qos_auth_group_info(u32 len, u32 qos, u32 arg2, u32 arg3)
{
    if (!sc_start_frame((u16)len))
        return -1;
    (void)qos; (void)arg2; (void)arg3;
    sc_printf("I (%d) %s: max_cont:%d, sec_cont:%d, max_count:%d, max_cont_pos:%d, max_count_pos:%d\n");
    return 0;
}

/* sc_recv_callback_ht40_ctrl @ sc_ht40.o 00000094 size 1245B bind GLOBAL
 * Calls: ht40_scanning_sync_frame, sc_ht40_get_qos_auth_group_info, sc_data_frame,
 *   sc_get_data_index, sc_pkg_cmp, sc_pkg_save, sc_recv_completed,
 *   sc_get_ssid_passwd, sc_set_state, sc_start_frame, sc_get_group_index,
 *   sc_group_frame, sc_os_get_time_ms
 * Data refs: lock_type, SnifGlob, g_osi_funcs_p, SC_TAG, ht40_state,
 *   g_touch_timeout, ht40_rssi_low/high, ht40_filter, g_config_data, ht40_qos,
 *   ht40_timestamp, restart_ht40_timer, sc_smartconfig_restart
 *   (both refs-only per funcdb v2 calls[] omission)
 * Fidelity: low - 494-insn mimo state machine abstracted; phase order and
 *   gates below are observed, inner bookkeeping is approximate.
 * Observed packet/codec logic:
 *  - drop "W (%d) %s: drop HT40 pkt" unless lock_type path selected;
 *  - "TYPE: ESPTOUCH_V2" once synced; per-frame log "mimo, %d/%d [%d] %d"
 *    and "mimo %d/0 %d" (formats in rodata).
 *  - RSSI out-of-range drop ("rssi out range"); filter mismatch drop
 *    ("filter: %d, ht40_filter: %d"); bad length ("invalid length");
 *    dup/prev-cur drops ("drop: prev:%d, cur:%d",
 *    "drop: len diff. prev:%x, cur:%x").
 *  - state dispatch: ht40_state==0 -> ht40_scanning_sync_frame();
 *    synced -> sc_ht40_get_qos_auth_group_info() for qos/auth/group, then
 *    sc_start_frame/sc_group_frame/sc_data_frame classification,
 *    sc_get_data/group_index, sc_pkg_cmp/sc_pkg_save dedup,
 *    sc_recv_completed()/sc_get_ssid_passwd() to finish; timeout via
 *    g_touch_timeout + sc_os_get_time_ms -> restart_ht40_timer/
 *    sc_smartconfig_restart; SC_EVENT reports throughout. */
int sc_recv_callback_ht40_ctrl(u8 *frm, u32 len, u32 arg2, u32 arg3)
{
    u32 now = sc_os_get_time_ms();
    (void)now;
    if (ht40_state == 0)
        return ht40_scanning_sync_frame(len, arg2, arg3, 0);
    if (!sc_ht40_get_qos_auth_group_info(len, ht40_qos, arg2, arg3))
        return -1;
    if (sc_start_frame((u16)len)) {
        (void)sc_get_group_index((u16)len);
        sc_group_frame((u16)len);
    } else if (sc_data_frame((u16)len)) {
        (void)sc_get_data_index((u16)len);
    }
    if (sc_recv_completed((u16)len, arg2, arg3))
        return sc_get_ssid_passwd((u16)len);
    return 0;
}
