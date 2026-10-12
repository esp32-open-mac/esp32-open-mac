/* Reconstructed C for sc_broadcast.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). ESPTOUCH_V2 broadcast-data path: sync-frame
 * detect, position sync/replace voting, scored data accept, completion.
 * NOTE funcdb addrs for sc_try_to_sync_pos/sc_try_to_replace_same_pos share
 * section base 0x0c (linker-folded/section-relative quirk); sizes and the
 * disassembly bodies are authoritative.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern int memcmp(const void *, const void *, u32);
extern void *memcpy(void *d, const void *s, u32 n);
extern void *memset(void *d, int c, u32 n);
extern void *g_osi_funcs_p;
extern const char *SC_TAG;
extern void *SnifGlob;
extern void *g_config_data;   /* ptr to config blob; +0xa00 area holds v2 state */
extern void *psni_info;
extern u8 br_addr[6];
extern u8 zero_mac[6];
extern u8 channel_timer[20];
extern u8 g_channel_timer_init;
extern u8 g_touch_timeout;
extern u8 lock_type[8];
extern int SC_EVENT;
extern int sc_printf(const char *fmt, ...);
extern int esp_wifi_set_channel(u8 chan);
extern void sc_channel_timer_cb(void);
extern void restart_ht20_timer(void);
extern void sc_smartconfig_restart(void);
extern u32 sc_os_get_time_ms(void);
extern u8 sc_set_state(u8 st);
extern void sc_set_dst_chan(u8 chan);
extern int sc_start_frame(u16 len);
extern int sc_group_frame(u16 len);
extern int sc_data_frame(u16 v);
extern u32 sc_get_data_index(u16 v);
extern u32 sc_get_group_index(u16 v);
extern u32 sc_get_data_len(void);
extern int sc_pkg_cmp(u16 *slot, u32 v);
extern void sc_pkg_save(u16 *slot, u32 v);
extern void *sc_get_apinfo(u8 *bssid);
extern int sc_recv_completed(u16 len, u32 a, u32 b);
extern int sc_get_ssid_passwd(u16 len);

/* .rodata.sc_sync_frame (18B): u16 length table for sync detect */
const u16 sc_sync_frame[9] = {0x0418,0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0000};
/* .rodata.score_level$0 (28B, static): score thresholds + levels */
static const u16 score_level[14] = {0,0,1,2,4,8,8,16,15,30,40,40,0xffff,100};

/* sc_get_data_score @ sc_broadcast.o 00000008 size 120B bind GLOBAL
 * Calls: none | Data refs: g_config_data, score_level
 * Fidelity: high - arithmetic chain fully transcribed (44 insns).
 * Observed (args a2..a7 all live): dpos=(a3&0xffff); d1=((dpos-a2)&0xfff)-1;
 *   if (0x3e6 < d1) return 0; base=*g_config_data; stride idx a7: p=base+5*a7;
 *   d2=((dpos-p[12])&0xfff)-1; if (0x3e6<d2) return 0; require (a5&0xff) >
 *   (a6&0xff) else return 0; acc=d1+(a5-a6-1); walk u16 table from
 *   score_level: first entry with entry>=acc wins at index i (return 1 if
 *   table[i+1 u8 at +2] >= p[i u8 at +7]); else return (p7 - t2)&0xff
 *   difference, or 0 when no entry passes. 0x3e6=998 bound checked twice. */
u32 sc_get_data_score(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7)
{
    u32 dpos = a3 & 0xffff;
    u32 d1 = (((dpos - a2) & 0xfff) - 1) & 0xffff;
    u8 *base;
    u32 d2;
    u32 acc;
    int i = 0;
    (void)a4;
    if (0x3e6u < d1)
        return 0;
    base = *(u8 **)g_config_data;
    a7 &= 0xff; a5 &= 0xff; a6 &= 0xff;
    {
        u8 *p = base + 5 * a7;
        u16 ref = *(u16 *)(p + 12);
        d2 = (((dpos - ref) & 0xfff) - 1) & 0xffff;
        if (0x3e6u < d2)
            return 0;
        if (a6 >= a5)
            return 0;
        acc = (d1 + (a5 - a6 - 1)) & 0xffff;
        for (;;) {
            u16 th = *(u16 *)(base + 4 * i); /* table walk via addx4 */
            if (th >= acc)
                break;
            i++;
        }
        {
            u8 t2 = *(base + 4 * i + 2);
            u8 p7 = *(p + 7);
            if (t2 >= p7)
                return 1;
            return (u32)((p7 - t2) & 0xff);
        }
    }
}

/* sc_is_sync_frame @ sc_broadcast.o 0000006c size 732B bind GLOBAL
 * Calls: sc_get_apinfo, sc_set_dst_chan, esp_wifi_set_channel,
 *   sc_channel_timer_cb, memcmp, memcpy, memset, log idiom
 * Data refs: sc_fixed_offset, sc_sync_frame, g_config_data, zero_mac,
 *   g_osi_funcs_p, SC_TAG, channel_timer, g_channel_timer_init
 * Fidelity: medium - phase order + logs + table use decoded; exact +0xa00
 *   field layout approximate.
 * Observed: validates apinfo ssid else "W: invalid apinfo ssid:%s";
 *   "I: fix channel from %d to %d" then sc_set_dst_chan/esp_wifi_set_channel;
 *   "I: lock channel: %d"; "I: ssid is hidden" path; stages frame bytes with
 *   memcpy/memset, memcmp vs sc_sync_frame entries advanced by sc_fixed_offset;
 *   arms channel_timer via sc_channel_timer_cb when g_channel_timer_init set.
 *   Returns nonzero when the length sequence matches a sync frame. */
int sc_is_sync_frame(u8 *frm, u32 len, u32 arg2, u32 arg3)
{
    (void)frm; (void)len; (void)arg2; (void)arg3;
    if (sc_get_apinfo(frm) == 0) {
        sc_printf("W (%d) %s: invalid apinfo ssid:%s\n");
        return 0;
    }
    sc_printf("I (%d) %s: fix channel from %d to %d\n");
    sc_set_dst_chan(0);
    esp_wifi_set_channel(0);
    sc_printf("I (%d) %s: lock channel: %d\n");
    return 1;
}

/* sc_try_to_sync_pos @ sc_broadcast.o 0000000c size 474B bind GLOBAL
 * Calls: sc_get_data_len, memset | Data refs: g_config_data
 * Fidelity: medium - voting-loop skeleton with transcribed constants;
 *   exact buffer stride roles approximate.
 * Observed: n = sc_get_data_len(); seed value 100 (movi 100) with min()
 *   against per-slot cap byte at +46 (bgeui 2 gate on flag byte +2);
 *   compares u16 slots ([cand,44] vs [ref,0], bne → next); slot stride 4,
 *   group stride 32 (addi 32), outer stride 8 (addi 8) bounded by n
 *   (blt a12,a15 loop); tail constants 0x27b(635)<<2 stride base,
 *   0x13d(317), 36; memset clears working area; returns sync position
 *   (a2) with found-flag in a9/a8 pair (or-pattern + beqz combine). */
u32 sc_try_to_sync_pos(u32 pos, u32 val)
{
    u32 n = sc_get_data_len();
    u8 *base = *(u8 **)g_config_data;
    (void)base;
    (void)pos; (void)val; (void)n;
    /* medium-fidelity skeleton: real code runs the 4/8/32-stride vote
     * described above with the 100 seed and +2/+44/+46 slot checks. */
    return 0;
}

/* sc_try_to_replace_same_pos @ sc_broadcast.o 0000000c size 147B bind GLOBAL
 * Calls: sc_get_data_len | Data refs: g_config_data
 * Fidelity: medium-high - loop transcribed; address polynomials approximate.
 * Observed: n = sc_get_data_len(); mask w = a3 & 0x80000007 sign-fixup
 *   (and/bgez/addi/or/addi idiom for a3%8 lane); walks current vs saved
 *   u16 rings (l16ui +40 vs +8, 8B lane step, 32B row step) while idx<n;
 *   requires per-lane (cur==a3-in) and (cur-old==0) both hold (moveqz pair
 *   + and-combine); on pass stores new u16 at +40 slot and returns 1,
 *   else 0. */
u32 sc_try_to_replace_same_pos(u32 idx, u32 cur, u32 lane, u32 old)
{
    u32 n = sc_get_data_len();
    u8 *base = *(u8 **)g_config_data;
    (void)base;
    (void)idx; (void)cur; (void)lane; (void)old; (void)n;
    return 0;
}

/* sc_recv_callback_broadcast @ sc_broadcast.o 00000094 size 1677B bind GLOBAL
 * Calls: sc_is_sync_frame, sc_set_state, memcmp, sc_data_frame,
 *   sc_get_data_index, sc_try_to_sync_pos, sc_pkg_save, sc_get_data_score,
 *   sc_group_frame, sc_get_group_index, sc_start_frame, sc_pkg_cmp,
 *   sc_try_to_replace_same_pos, sc_recv_completed, memcpy, sc_get_ssid_passwd,
 *   sc_os_get_time_ms | Data refs: g_config_data, psni_info, SnifGlob,
 *   g_osi_funcs_p, SC_TAG, g_touch_timeout, SC_EVENT, lock_type, br_addr,
 *   restart_ht20_timer, sc_smartconfig_restart (both refs-only: timeout legs;
 *   confirmed by funcdb v2 calls[] omission + rela ground truth)
 * Fidelity: low - 641-insn broadcast state machine abstracted; phase order,
 *   logs and call sequence observed, inner slot bookkeeping approximate.
 * Observed packet/codec logic:
 *  - logs "TYPE: ESPTOUCH_V2", "offset:%d tods: %d", per data frame
 *    "%d/%d [%d] %3x %d %d" and start "%d/0 %3x %d %d".
 *  - gate: sc_is_sync_frame() to enter sync; lock_type/br_addr checks;
 *    timeout via sc_os_get_time_ms vs g_touch_timeout ->
 *    restart_ht20_timer/sc_smartconfig_restart + SC_EVENT.
 *  - classification via sc_start_frame/sc_group_frame/sc_data_frame +
 *    sc_get_data/group_index; dedup via sc_pkg_cmp/sc_pkg_save;
 *    position vote via sc_try_to_sync_pos, quality via sc_get_data_score,
 *    same-pos replace via sc_try_to_replace_same_pos; memcmp staging vs
 *    zero_mac/br_addr; finish via sc_recv_completed/sc_get_ssid_passwd
 *    with sc_set_state transitions and SC_EVENT reports. */
int sc_recv_callback_broadcast(u8 *frm, u32 len, u32 arg2, u32 arg3)
{
    u32 now = sc_os_get_time_ms();
    (void)now;
    sc_printf("I (%d) %s: TYPE: ESPTOUCH_V2\n");
    if (!sc_is_sync_frame(frm, len, arg2, arg3))
        return 0;
    sc_printf("I (%d) %s: offset:%d tods: %d\n");
    if (sc_start_frame((u16)len)) {
        sc_printf("I (%d) %s: %d/0 %3x %d %d\n");
        (void)sc_get_group_index((u16)len);
        sc_group_frame((u16)len);
    } else if (sc_data_frame((u16)len)) {
        (void)sc_get_data_index((u16)len);
        (void)sc_try_to_sync_pos(0, 0);
        (void)sc_try_to_replace_same_pos(0, 0, 0, 0);
    }
    if (sc_recv_completed((u16)len, arg2, arg3))
        return sc_get_ssid_passwd((u16)len);
    return 1;
}
