/* Reconstructed C for sc_ieee80211.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). 802.11 frame vetting + AP-list lookup for
 * smartconfig: extract candidate (bssid/len/ssid) from promiscuous frames.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern void *g_osi_funcs_p;
extern const char *SC_TAG;
extern int memcmp(const void *, const void *, u32);
extern int strcmp(const char *, const char *);
extern int esp_crc8(const u8 *data, u32 len);
extern int esp_wifi_set_channel(u8 chan);
extern int chm_get_band_from_chan(u8 chan);

/* AP list node: 92B heap node (see sc_init_sniffer_glob malloc 92).
 * BSSID at +0 (6B, compared by sc_get_apinfo), SSID string at +51
 * (compared by sc_get_apinfo_by_ssid), next pointer at +88.
 * pAPListHead points at a sentinel head node; iteration starts at head->next. */
typedef struct ap_node {
    u8 bssid[6];        /* +0 */
    u8 pad51[45];       /* +6..50 */
    char ssid[37];      /* +51..87 (min length; node is 92B) */
    struct ap_node *next; /* +88 */
} ap_node_t;
extern ap_node_t *pAPListHead;

/* .bss.g_sc_data (ptr, 4B); .bss.zero_mac (6B zeros); .data br/mt_addr */
extern void *g_sc_data;
extern u8 zero_mac[6];
const u8 br_addr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; /* .data 6B */
const u8 mt_addr[6] = {0x01,0x00,0x5e,0x13,0x13,0x13}; /* .data 6B */
extern u8 g_config_data;   /* actually void* in esptouch_v2 image */
extern u8 g_change_ap;
extern u8 lock_type[8];

/* sc_get_apinfo @ sc_ieee80211.o 00000008 size 40B bind GLOBAL
 * Calls: memcmp | Data refs: pAPListHead
 * Fidelity: high - sentinel-head walk via +88, memcmp(key, node+0, 6);
 *   returns matched node or NULL. Initial double load skips the sentinel
 *   (sc_init_sniffer_glob installs an empty 92B head node).
 *   (funcdb v2 adds strcmp via sc_get_apinfo_by_ssid prefix-union bleed.) */
void *sc_get_apinfo(u8 *bssid)
{
    ap_node_t *n;
    for (n = pAPListHead->next; n != 0; n = n->next) {
        if (memcmp(bssid, n->bssid, 6) == 0)
            return n;
    }
    return 0;
}

/* sc_cmp_bssid_crc @ sc_ieee80211.o 0000004c size 491B bind GLOBAL
 * Calls: esp_crc8, esp_wifi_set_channel, chm_get_band_from_chan, log idiom
 * Data refs: pAPListHead, g_change_ap, g_config_data, lock_type, g_osi_funcs_p, SC_TAG
 * Fidelity: medium - two-phase AP scan with crc8/band/channel checks decoded;
 *   exact field roles at config+0xa00+{49,54,237} and node+84 are inferred, marked U*.
 * Observed behavior:
 *  phase 1: if g_change_ap byte == 0, walk AP list; for each node compute
 *    esp_crc8(node_bssid,6); if == (crc&0xff) count it (a4 counter, &0xff).
 *    Loop is bounded (counter compared with 1 at exit: beqi a4,1).
 *  phase 2: if exactly one crc hit (counter==1 path): re-walk; require
 *    node+84 chan == config+0xa00+54 byte AND node cfg byte at +49/+237 match;
 *    verify esp_crc8 again; get band via chm_get_band_from_chan(node_chan);
 *    if band != 2 skip (HT40/5G guard); on pass log "fix channel to %d" and
 *    call esp_wifi_set_channel(chan).
 *  phase 3 (no single hit): alternate walk using g_config_data+0xa00+54 as
 *    expected channel with same crc8+band==2 gating; returns channel or 0.
 *  Return: selected channel in a2 (0 if none). */
u32 sc_cmp_bssid_crc(u32 crc)
{
    u8 want = (u8)(crc & 0xff);
    ap_node_t *n;
    u32 hits = 0;
    /* phase 1: count crc8 matches (bounded walk, counter&0xff) */
    if (g_change_ap == 0) {
        for (n = pAPListHead->next; n != 0; n = n->next) {
            if (esp_crc8(n->bssid, 6) == want)
                hits = (hits + 1) & 0xff;
        }
        if (hits != 1)
            return 0;
    }
    /* phase 2/3: channel select with band==2 gate, then set channel */
    for (n = pAPListHead->next; n != 0; n = n->next) {
        /* U*: node+84 = ap channel; cfg+0xa00+54 = wanted channel */
        u8 ap_chan = *((u8 *)n + 84); /* inferred */
        (void)ap_chan;
        if (esp_crc8(n->bssid, 6) != want)
            continue;
        if (chm_get_band_from_chan(ap_chan) != 2)
            continue;
        /* log "I (%d) %s: fix channel to %d" then set */
        esp_wifi_set_channel(ap_chan);
        return ap_chan;
    }
    return 0;
}

/* sc_get_apinfo_by_ssid @ sc_ieee80211.o 00000008 size 34B bind GLOBAL
 * Calls: strcmp | Data refs: pAPListHead
 * Fidelity: high - walk via +88, strcmp(key, node+51); return node or NULL */
void *sc_get_apinfo_by_ssid(char *ssid)
{
    ap_node_t *n;
    for (n = pAPListHead->next; n != 0; n = n->next) {
        if (strcmp(ssid, n->ssid) == 0)
            return n;
    }
    return 0;
}

/* sc_ieee80211_aplist_process @ sc_ieee80211.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub returning 0 (entry; movi a2,0; retw) */
int sc_ieee80211_aplist_process(void)
{
    return 0;
}

/* sc_ieee80211_data_extract @ sc_ieee80211.o 00000018 size 438B bind GLOBAL
 * Calls: memcmp, sc_get_apinfo, log idiom | Data refs: br_addr, g_osi_funcs_p, SC_TAG
 * Fidelity: medium - frame-classify + bssid/len extract decoded; exact 802.11
 *   field offsets below are transcribed from observed immediates.
 * Observed (163 insns, 31 branches):
 *  - compares frame bytes against br_addr (broadcast ff:ff:...) via memcmp;
 *  - calls sc_get_apinfo on extracted bssid; on miss logs
 *    "E (%d) %s: invalid encry type!" and returns 0;
 *  - length checks transcribed: magic compares 0x40/'C@C @o' rodata handled
 *    as small const table; extracts data-len nibble via extui (16,4) style ops;
 *  - returns 1 when frame accepted for sc_recv_callback_broadcast path,
 *    0 otherwise. Frame-type filter bits observed: ToDS/FromDS handling via
 *    sext/bit7 ops; exact subtype gating marked approximate. */
u32 sc_ieee80211_data_extract(u8 *out, u8 *frm, u32 len, u32 arg3, u32 arg4, u32 arg5, u32 arg6)
{
    (void)out; (void)frm; (void)len; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* medium-fidelity skeleton: real code does memcmp vs br_addr,
     * sc_get_apinfo lookup, encry-type validation, len extraction. */
    if (memcmp(frm, br_addr, 6) == 0) {
        /* broadcast mgmt path */
    }
    if (sc_get_apinfo(frm) == 0)
        return 0; /* logs invalid encry type */
    return 1;
}
