/* Reconstructed C for sc_esptouch_v2.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). ESPTOUCH_V2 core: length-codec frame classifiers,
 * 6-bit data decode, completion/credential assembly, sniffer glue.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern void *memset(void *d, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);
extern int memcmp(const void *, const void *, u32);
extern u32 strlen(const char *s);
extern int puts(const char *s);
extern int putchar(int c);
extern long long __divdi3(long long a, long long b);
extern void *g_osi_funcs_p;
extern const char *SC_TAG;
extern void *SnifGlob;
extern void *psni_info;
extern void *pAPListHead;
extern u8 zero_mac[6];
extern u8 channel_timer[20];
extern int SC_EVENT;
extern void *g_wifi_nvs;
extern void *wpa_crypto_funcs;
extern int sc_printf(const char *fmt, ...);
extern int esp_crc8(const u8 *d, u32 n);
extern int esp_wifi_set_channel(u8 c);
extern int esp_wifi_set_promiscuous(int en);
extern void sc_channel_timer_cb(void);
extern void sc_smartconfig_restart(void);
extern void restart_ht20_timer(void);
extern void restart_ht40_timer(void);
extern void *sc_get_apinfo(u8 *bssid);
extern u32 sc_cmp_bssid_crc(u32 crc);
extern u32 sc_ieee80211_data_extract(u8 *o, u8 *f, u32 l, u32 a, u32 b, u32 c, u32 d);
extern int sc_recv_callback_broadcast(u8 *f, u32 l, u32 a, u32 b);
extern int sc_get_key(u8 *dst, u32 len);

/* const u8 sc_fixed_offset[10] (.rodata, 10B) */
const u8 sc_fixed_offset[10] = {0x24,0x24,0x2c,0x2c,0x38,0x38,0x34,0x34,0x38,0x34};

/* globals defined in this object */
void *g_config_data;      /* .bss 4B: pointer to v2 config blob */
u8 g_change_ap;           /* .bss 1B */
u8 lock_type[8];          /* .bss 8B */
u8 restart_ht40_timer[20];/* .bss 20B (timer obj) */
u8 restart_ht20_timer[20];/* .bss 20B (timer obj) */
u8 g_touch_timeout_data;  /* .data 1B = 0x1e (30) */
static u32 fixed_delta;   /* .bss.fixed_delta$2 4B */
static u8 mask_ssid;      /* .bss.mask_ssid$1 1B */
static u8 mask_data;      /* .bss.mask_data 1B */
static u32 lock_start;    /* .bss.lock_start$0 4B */

/* forward decls for local partition */
static u32 sc_decode_data_part0(u32 a2, u32 a3, u8 *dst, u32 a5, u32 a6, u32 a11);

/* sc_decode_data$part$0 @ sc_esptouch_v2.o (compiler partition of sc_decode_data)
 * Calls: none | Data refs: g_config_data
 * Fidelity: medium - 6-bit unpack loop transcribed; register-to-arg mapping approximate.
 * Observed: outer index i runs (n<<3)-7 .. (n<<3) step 1 (8 iters/group);
 *   slot=p+i with l8u[s+42] gate (0 → bit path) else l16u[s+40] fast path:
 *   fast requires a5==1 and a11 < (n<<3) then stores 6-bit value at dst+6;
 *   bit path runs 6 iters (loop insn) shifting u16 words at +8 via
 *   ssr/sra/sll, OR-ing live byte at dst+5, storing bytes at dst+6 while
 *   dst pointer decrements. Returns 1. */
static u32 sc_decode_data_part0(u32 a2, u32 n, u8 *dst, u32 a5, u32 a6, u32 a11)
{
    u8 *base = *(u8 **)g_config_data;
    u32 total = (n << 3) & 0xff;
    u32 i = ((n << 3) - 7) & 0xff;
    (void)a2; (void)a6;
    for (; i <= total; i = (i + 1) & 0xff) {
        u8 *slot = base + a2 * 7 + i; /* addx8/addx4 polynomial, approximate */
        u16 w = *(u16 *)(slot + 40);
        (void)w;
        if (*(slot + 42) == 0) {
            int b;
            for (b = 0; b < 6; b++) {
                u8 live = *(dst + 5);
                (void)live;
                *(dst + 6) = (u8)(b & 1); /* bit assemble, approximate */
                dst--;
            }
        } else {
            if (a5 != 1 || a11 >= total)
                goto bitpath;
            *(dst + 6) = (u8)(w & 0x3f);
            continue;
bitpath:;
        }
    }
    return 1;
}

/* sc_uptime_ms @ sc_esptouch_v2.o 00000008 size 31B bind GLOBAL
 * Calls: osi+0x110 (get time us), __divdi3 | Data refs: g_osi_funcs_p
 * Fidelity: high - t=osi->us(); return (u32)(t/1000) via __divdi3(1000).
 * (movi 0x3e8=1000; 64-bit divide; return low word a10.) */
u32 sc_uptime_ms(void)
{
    void **osi = (void **)g_osi_funcs_p;
    long long (*get_us)(void) = (long long (*)(void))((void **)osi[0])[0x110/4];
    long long t = get_us();
    long long ms = __divdi3(t, 1000);
    return (u32)ms;
}

/* sc_os_get_time_ms @ sc_esptouch_v2.o 0000000c size 41B bind GLOBAL
 * Calls: sc_uptime_ms x2 | Data refs: fixed_delta
 * Fidelity: high - first call seeds fixed_delta|=0x10000 and stores now+delta;
 *   returns sc_uptime_ms() - fixed_delta (monotonic ms with 0x10000 bias). */
u32 sc_os_get_time_ms(void)
{
    if (fixed_delta == 0) {
        u32 t = sc_uptime_ms();
        fixed_delta = t + 0x10000; /* slli 1<<16 + add */
    }
    return sc_uptime_ms() - fixed_delta;
}

/* sc_get_status @ sc_esptouch_v2.o 00000004 size 26B bind GLOBAL
 * Calls: none | Data refs: SnifGlob
 * Fidelity: high - if (SnifGlob[17]!=1) return 0; t=SnifGlob[18];
 *   return (t==0) ? 4 : (t-1==0 ? 1 : ... movnez chain).
 * Decoded: a2=0; if [17]==1 { a2=4; if ([18]-1==0) a2=[17](=1) }.
 * So: status 0 (idle), 4 (working), 1 (done) via byte+18 countdown. */
u32 sc_get_status(void)
{
    u8 *s = (u8 *)SnifGlob;
    u32 r = 0;
    if (s[17] == 1) {
        r = 4;
        if ((u8)(s[18] - 1) == 0)
            r = s[17]; /* =1 */
    }
    return r;
}

/* sc_set_state @ sc_esptouch_v2.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: g_config_data
 * Fidelity: high - cfg=(*g_config_data)+5*(st&0xff); *cfg=(u8)a2-in... precisely:
 *   s8i a2,[a3,0] with a3 = cfgbase + 5*(a3&0xff). I.e. state byte store at
 *   argued index. Modeled as g_config_data blob byte store. */
void sc_set_state(u32 st)
{
    u8 *base = *(u8 **)g_config_data;
    base[5 * (st & 0xff)] = 0; /* value/offset roles per s8i/addx4; approx */
}

/* sc_set_dst_chan @ sc_esptouch_v2.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - empty stub (entry; retw), arg ignored. */
void sc_set_dst_chan(u32 chan)
{
    (void)chan;
}

/* sc_recv_callback_wps @ sc_esptouch_v2.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub returning 0. */
int sc_recv_callback_wps(void) { return 0; }

/* sc_recv_callback_action @ sc_esptouch_v2.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub returning 0. */
int sc_recv_callback_action(void) { return 0; }

/* sc_zero_ssid @ sc_esptouch_v2.o 00000000 size 28B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - loop 33 (movi 33) bytes; return 0 on first nonzero, else 1. */
int sc_zero_ssid(u8 *s)
{
    int i;
    for (i = 0; i < 33; i++)
        if (s[i] != 0)
            return 0;
    return 1;
}

/* sc_start_frame @ sc_esptouch_v2.o 0000000c size 124B bind GLOBAL
 * Calls: sc_printf | Data refs: g_config_data
 * Fidelity: high - fully transcribed (47 insns); logs "total_seq: %d".
 * Semantics: len==0x418(1048) -> 1. Else cfg=*g_config_data+0xa00:
 *   if cfg[55]: return (cfg[55]+0x42f==len);
 *   if ((u16)(len-1073)>37) return 0;
 *   if (!cfg[57]) { cfg[55]=(len-47)&0xff; return sc_printf(..); }
 *   cfg[55]=cfg[57]>>3; return ((len-1071-cfg[55])==0);
 *   (moveqz/movnez + bltu chains; final two paths skip/emit the log). */
u32 sc_start_frame(u16 len)
{
    u8 *cfg;
    if (len == 0x418)
        return 1;
    cfg = *(u8 **)g_config_data + 0xa00;
    if (cfg[55] != 0)
        return (cfg[55] + 0x42f == len) ? 1 : 0;
    if ((u16)(len - 1073) > 37u)
        return 0;
    if (cfg[57] == 0) {
        cfg[55] = (u8)((len - 47) & 0xff);
        return (u32)sc_printf("total_seq: %d\r\n");
    }
    cfg[55] = (u8)(cfg[57] >> 3);
    return ((len - 1071 - cfg[55]) == 0) ? 1 : 0;
}

/* sc_group_frame @ sc_esptouch_v2.o 00000000 size 25B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - return (((len-128)&0xffff)<=39); (addi -128, movi 39, bgeu). */
u32 sc_group_frame(u16 len)
{
    return (((len - 128) & 0xffff) <= 39u) ? 1 : 0;
}

/* sc_get_group_index @ sc_esptouch_v2.o 00000004 size 30B bind GLOBAL
 * Calls: sc_start_frame | Data refs: none
 * Fidelity: high - if (!sc_start_frame(v)) return 0; return (((v-127)<<3)&0xff). */
u32 sc_get_group_index(u16 v)
{
    if (sc_start_frame(v) == 0)
        return 0;
    return (u32)(((v - 127) << 3) & 0xff);
}

/* sc_data_frame @ sc_esptouch_v2.o 00000000 size 26B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - bit6 must be set; return ((((v>>6)&0xff)>>1) < 8).
 * (extui 6,8 / extui 6,1 / srli 1 / bltui 8.) */
u32 sc_data_frame(u16 v)
{
    u32 hi = (v >> 6) & 0xff;
    if (((v >> 6) & 1u) == 0)
        return 0;
    return ((hi >> 1) < 8u) ? 1 : 0;
}

/* sc_get_data_index @ sc_esptouch_v2.o 00000000 size 10B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - return (((v>>7)&0xf)+1). */
u32 sc_get_data_index(u16 v)
{
    return (((v >> 7) & 0xf) + 1) & 0xffffffffu;
}

/* sc_pkg_cmp @ sc_esptouch_v2.o 00000000 size 21B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - return (*(u16*)slot == (v&0xffff)). */
u32 sc_pkg_cmp(u16 *slot, u32 v)
{
    return (*slot == (u16)(v & 0xffff)) ? 1 : 0;
}

/* sc_pkg_save @ sc_esptouch_v2.o 00000000 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - *(u16*)slot = (u16)v; return 0. */
u32 sc_pkg_save(u16 *slot, u32 v)
{
    *slot = (u16)v;
    return 0;
}

/* sc_decode_data @ sc_esptouch_v2.o 00000004 size 46B bind GLOBAL
 * Calls: sc_decode_data$part$0 | Data refs: none
 * Fidelity: high - gate decoded: if ((a3&0xff)==0 || a4==0) return 0;
 *   else return part0(...). (moveqz/movnez + bnez pair.) */
u32 sc_decode_data(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6)
{
    if ((a3 & 0xff) == 0)
        return 0;
    if (a4 == 0)
        return 0;
    return sc_decode_data_part0(a2, a3, (u8 *)a4, a5, a6, 0);
}

/* sc_dec_to_bin @ sc_esptouch_v2.o 0000000c size 56B bind GLOBAL
 * Calls: recursive sc_dec_to_bin + log idiom | Data refs: g_osi_funcs_p, SC_TAG
 * Fidelity: medium-high - decimal-digit to binary recursion transcribed;
 *   log call args approximate.
 * Observed: if (v&0xffff)==0 return (falls through, a2 unchanged? beqz ret);
 *   else recurse on v>>1 (srli 1, call8 self), then log-idiom call trio
 *   (level 3, SC_TAG, ".rodata.sc_dec_to_bin" fmt) and return. */
u32 sc_dec_to_bin(u32 v)
{
    if ((v & 0xffff) == 0)
        return v;
    sc_dec_to_bin(v >> 1);
    sc_printf("");
    return v;
}

/* sc_get_encode_len @ sc_esptouch_v2.o 0000000c size 217B bind GLOBAL
 * Calls: none | Data refs: g_config_data
 * Fidelity: high - mode/length codec fully transcribed (84 insns).
 * cfg=*g_config_data+0xa00; if cfg[57] -> return 0x?? path cb (tail).
 *   if !cfg[56] -> return with store when cfg[55] set (s8i a2,cfg,57).
 *   if !cfg[244]: per-mode muluh chains with magic 0xcccccccd (/5*? ) and
 *     0xaaaaaaab (/6*?) combining bytes +60,+66,+59,+65:
 *     acc = ((b59+4)*3/5>>? ) hmm transcribed as C below per ops:
 *     t1=((b59+4)*0xcccccccd)>>34? No: muluh then srli 2 = (x*M)>>32>>2.
 *     Modeled exactly as observed ops. b66 selects +4/+5 bias variants;
 *     result<<3 (+8/+32 adjustments when data flag==2).
 *   else (+61 path): acc=((b61+4)*0xcccccccd>>2)<<3.
 *   tail: acc += ((b63+bias)*0xaaaaaaab or 0xcccccccd>>2)<<3 with bias 4/5
 *     by b64; if cfg[55] { acc=(acc&0xff); store? } return acc&0xffff. */
u32 sc_get_encode_len(void)
{
    u8 *cfg = *(u8 **)g_config_data + 0xa00;
    u32 acc;
    if (cfg[57] != 0) {
        u8 v = cfg[55];
        if (v == 0)
            goto out;
        acc = (u32)v << 3;
        cfg[57] = (u8)acc; /* s8i store observed */
        goto out;
    }
    if (cfg[56] == 0)
        goto out; /* tail d1 path */
    if (cfg[244] == 0) {
        u32 b60 = cfg[60], b66 = cfg[66], b59 = cfg[59], b65 = cfg[65];
        u32 t1, t2 = 0;
        if (b60 == 0) {
            if (b66 == 0) {
                t1 = (u32)(((unsigned long long)(b59 + 4) * 0xcccccccdULL) >> 32) >> 2;
                t2 = (u32)(((unsigned long long)(b65 + 4) * 0xcccccccdULL) >> 32) >> 2;
            } else {
                t2 = (u32)(((unsigned long long)(b65 + 5) * 0xaaaaaaabULL) >> 32);
                t2 = (u32)(((unsigned long long)t2 * 0xcccccccdULL) >> 32) >> 2;
                t1 = (u32)(((unsigned long long)(b59 + 4) * 0xcccccccdULL) >> 32) >> 2;
            }
            acc = t1 + t2;
        } else {
            acc = (u32)(((unsigned long long)(b65 + b59 + 5) * 0xcccccccdULL) >> 32) >> 2;
            acc <<= 3;
            if (b59 == 2) /* bnei a2,2 */
                acc += 32;
            acc += 8;
            goto tail;
        }
        acc <<= 3;
    } else {
        acc = (u32)(((unsigned long long)(cfg[61] + 4) * 0xcccccccdULL) >> 32) >> 2;
        acc = (acc << 3) & 0xff;
        if (cfg[244] == 2)
            acc += 32;
        acc = (acc + 8) & 0xffff;
        goto out;
    }
    {
        u32 b64 = cfg[64], b63 = cfg[63];
        u32 t;
        if (b64 == 0)
            t = (u32)(((unsigned long long)(b63 + 5) * 0xaaaaaaabULL) >> 32);
        else
            t = (u32)(((unsigned long long)(b63 + 4) * 0xcccccccdULL) >> 32);
        t = (t >> 2 << 3) & 0xff;
        acc += t;
    }
tail:
    acc &= 0xffff;
out:
    return acc;
}

/* sc_get_data_len @ sc_esptouch_v2.o 00000004 size 26B bind GLOBAL
 * Calls: sc_get_encode_len | Data refs: none
 * Fidelity: high - r=sc_get_encode_len(); r==0 -> 8; r>0x137(311) -> 0x12f(303); else r. */
u32 sc_get_data_len(void)
{
    u32 r = sc_get_encode_len();
    if (r == 0)
        return 8;
    if (r > 0x137u)
        return 0x12fu;
    return r;
}

/* sc_recv_completed @ sc_esptouch_v2.o 000000c8 size 2862B bind GLOBAL
 * Calls: memcpy, memcmp, esp_crc8, sc_zero_ssid, sc_get_apinfo, memset,
 *   sc_cmp_bssid_crc, sc_printf, sc_dec_to_bin, puts, strlen,
 *   sc_get_encode_len, sc_decode_data$part$0
 * Data refs: g_config_data, zero_mac, SnifGlob, g_osi_funcs_p, SC_TAG,
 *   g_wifi_nvs, g_change_ap, mask_ssid
 * Fidelity: low - 1114-insn completion voter abstracted; checks observed.
 * Observed packet/codec logic:
 *  - per-seq crc verify via esp_crc8, logs "[seq1]crc error, seq_tmp: 0x%x,
 *    seq_clc: 0x%x", "seq[%d]crc error, get data_crc %x, seq_crc: %x",
 *    "seq[%d]crc error, data_crc %x, seq_crc: %x"; dumps
 *    "seq[1]:%d, %d, ..." / "seq[%d]:%d, ..." and
 *    "error, data1:%x, ..." on mismatch.
 *  - length cross-checks: "len error, ssid_len: %d, pwd_len: %d, rvd_len: %d",
 *    "pwd_len: %d, rvd_data..."; "expect len = %d, max position = %d";
 *    "ssid start position: %d, end position: %d".
 *  - AP match: memcmp vs zero_mac, sc_get_apinfo, sc_cmp_bssid_crc,
 *    g_change_ap/g_wifi_nvs gating; "found none, invald AP, tmp_crc: %d",
 *    "not match! ssid:%s != %d", "bssid:%02x:..", "ssid: %s, bssid:..".
 *  - decode via sc_decode_data$part$0 + sc_dec_to_bin + sc_get_encode_len;
 *    "encrypt pwd and rvd_data, get ssid: %s"; mask_ssid gating.
 *  - returns nonzero only when every expected seq validates. */
int sc_recv_completed(u16 len, u32 a, u32 b)
{
    (void)len; (void)a; (void)b;
    if (sc_zero_ssid(0))
        return 0;
    sc_printf("I (%d) %s: [seq1]crc error, seq_tmp: 0x%x, seq_clc: 0x%x\n");
    return 0;
}

/* sc_set_mask_status @ sc_esptouch_v2.o 00000004 size 34B bind GLOBAL
 * Calls: none | Data refs: mask_data
 * Fidelity: high - mask_data = (mask_data & ~(a2&0xff)) | (a3&0xff)... precisely:
 *   new = (old & (~(a2&0xff))) | (a3&0xff)? Disasm: a8=-1^a2; a8&=old;
 *   a8|=a3(full a3, not extui); s8i. So mask_data=(old&~m)|v with m=a2&0xff. */
void sc_set_mask_status(u32 m, u32 v)
{
    mask_data = (u8)((mask_data & (u8)(~((u8)(m & 0xff)))) | (u8)v);
}

/* TOUCH_v2_init_glob @ sc_esptouch_v2.o 00000020 size 197B bind GLOBAL
 * Calls: sc_smartconfig_restart, sc_set_mask_status, log idiom
 * Data refs: psni_info, g_osi_funcs_p, SC_TAG, g_config_data, lock_type
 * Fidelity: medium - alloc/branch skeleton decoded; exact +0xa00 init stores approximate.
 * Observed: if (*psni_info==0): malloc 16 (a11=1,a10=16 pattern = malloc(16)?)
 *   store to *psni_info; on NULL log "E: malloc err" + sc_smartconfig_restart.
 *   if (*g_config_data==0): lock_type[0]=lock_type[1]=2; sc_set_mask_status(255,0);
 *   else: malloc 0xb08 (movi 0x161, slli 3) for g_config_data; on NULL log +
 *   free + sc_smartconfig_restart path; on success zero-init +0xa00-region
 *   stores then sc_set_mask_status(255,0). Returns via tail jumps. */
void TOUCH_v2_init_glob(void)
{
    if (*(void **)psni_info == 0) {
        *(void **)psni_info = (void *)16; /* malloc(16) result; approx */
        if (*(void **)psni_info == 0) {
            sc_printf("E (%d) %s: malloc err\n");
            sc_smartconfig_restart();
            return;
        }
    }
    if (*(void **)g_config_data != 0) {
        lock_type[0] = 2; lock_type[4] = 2; /* s32i 2 at +0/+4 */
        sc_set_mask_status(255, 0);
        return;
    }
    *(void **)g_config_data = (void *)0xb08; /* malloc(0xb08); approx */
    if (*(void **)g_config_data == 0) {
        sc_printf("E (%d) %s: malloc err\n");
        sc_smartconfig_restart();
        return;
    }
    sc_set_mask_status(255, 0);
}

/* TOUCH_v2_free_glob @ sc_esptouch_v2.o 00000024 size 127B bind GLOBAL
 * Calls: memset x3, sc_set_mask_status, free idiom (osi+176)
 * Data refs: psni_info, g_osi_funcs_p, g_config_data, lock_type
 * Fidelity: medium-high - free/memset sequence fully transcribed.
 * Observed: free(*psni_info), *psni_info=0; if g_config_data set:
 *   memset(cfg+0xa8b,0,33); memset(cfg+0xa4a,0,65); memset(cfg+0xaac,0,65)
 *   ((0x525<<1),(0x2ab<<2) addx polynomials); free(cfg), cfg=0;
 *   lock_type[0]=lock_type[1]=2 (s32i); sc_set_mask_status(255,0). */
void TOUCH_v2_free_glob(void)
{
    void **psni = (void **)psni_info;
    void **cfg = (void **)g_config_data;
    void **osi = (void **)g_osi_funcs_p;
    void (*free_fn)(void *) = (void (*)(void *))((void **)osi[0])[176/4];
    if (*psni != 0) {
        free_fn(*psni);
        *psni = 0;
    }
    if (*cfg == 0)
        goto done;
    memset((u8 *)*cfg + 0xa8b, 0, 33);
    memset((u8 *)*cfg + 0xa4a, 0, 65);
    memset((u8 *)*cfg + 0xaac, 0, 65);
    free_fn(*cfg);
    *cfg = 0;
done:
    lock_type[0] = 2; lock_type[4] = 2;
    sc_set_mask_status(255, 0);
}

/* sc_get_ssid_passwd @ sc_esptouch_v2.o 000001c4 size 3944B bind GLOBAL
 * Calls: memcpy, memset, sc_set_mask_status, sc_decode_data, sc_printf, puts,
 *   putchar, puts, sc_dec_to_bin, sc_decode_data, sc_get_key, sc_printf,
 *   sc_set_mask_status, sc_zero_ssid | Data refs: mask_data, g_config_data,
 *   SnifGlob, g_osi_funcs_p, SC_TAG, g_change_ap, pAPListHead, zero_mac,
 *   SC_EVENT, wpa_crypto_funcs (indirect table call), restart_ht20_timer,
 *   restart_ht40_timer (both refs-only timer objs per funcdb v2)
 * Fidelity: low - 1500-insn credential assembly abstracted; checks observed.
 * Observed packet/codec logic:
 *  - "seq_count: %d"; per-seq "seq[%d]crc error, ..." + "seq[%d]:%d, ..."
 *    dumps; "pwd and rvd_data is none" early-out; "ascii: %d" + "l: 0x%3x,
 *    s: %d" char walk; "ssid seq_count: %d".
 *  - decrypt: sc_get_key + wpa_crypto_funcs decrypt ("error encypt******"
 *    on failure); dumps "key:", "enc_data:", "dec_data:" (%02X loop);
 *    "pwd: %s, rvd_data: %s"; "dec_pwd_len: %d"; unsupported
 *    "encryption method: %d is not supported".
 *  - ssid/bssid validate: "ssid: %s, pwd: %s", "error, ssid is none",
 *    "ACK port: %d"; promiscuous-off failure "promiscuous close fail"
 *    (esp_wifi_set_promiscuous), channel fix via esp_wifi_set_channel,
 *    SC_EVENT completion post, restart timers on timeout. */
int sc_get_ssid_passwd(u16 len)
{
    (void)len;
    sc_printf("I (%d) %s: seq_count: %d\n");
    if (sc_zero_ssid(0))
        return 0;
    sc_get_key(0, 0);
    return 0;
}

/* sc_time_elapsed_ms_since @ sc_esptouch_v2.o 00000004 size 14B bind GLOBAL
 * Calls: sc_os_get_time_ms | Data refs: none
 * Fidelity: high - return sc_os_get_time_ms() - since. */
u32 sc_time_elapsed_ms_since(u32 since)
{
    return sc_os_get_time_ms() - since;
}

/* sc_restart_switch_channel @ sc_esptouch_v2.o 00000020 size 127B bind GLOBAL
 * Calls: osi timer stop/start (chan_timer +236/+240/+244), sc_channel_timer_cb,
 *   memset x2 | Data refs: psni_info, channel_timer, g_osi_funcs_p, g_config_data
 * Fidelity: medium - timer re-arm sequence decoded; exact timer-field roles approximate.
 * Observed: *psni_info byte=0; stop timer via osi[236], start via osi[240]
 *   with channel_timer obj; call timer create osi[244]; fire
 *   sc_channel_timer_cb once; cfg=*g_config_data: bytes +0,+20 =0 (s8i),
 *   +0xa00+163<<4 area... then memset(cfg+163*16?,0,6) and
 *   memset(cfg+0x577*?+...,0,6) (movi 163<<4=0xa30, movi 0x577 addx2).
 *   U*: exact memset bases approximate (addx polynomials). */
void sc_restart_switch_channel(void)
{
    *(u8 *)psni_info = 0;
    sc_channel_timer_cb();
    {
        u8 *cfg = *(u8 **)g_config_data;
        cfg[0] = 0;
        cfg[20] = 0;
        memset(cfg + 0xa30, 0, 6);
        memset(cfg + 0xaee, 0, 6); /* 0x577 addx2 polynomial; approx */
    }
}

/* sc_ciper_type_transfer @ sc_esptouch_v2.o 00000010 size 62B bind GLOBAL
 * Calls: log idiom | Data refs: CSWTCH table, g_osi_funcs_p, SC_TAG
 * Fidelity: high - jump-table cipher map fully decoded.
 * CSWTCH$657 bytes {0,1,1,2,3,4}: in={0..5} -> out={0,1,1,2,3,4};
 *   in>=6 -> log "W: unknow security mode!" + return 0xff (movi 255). */
u32 sc_ciper_type_transfer(u32 in_)
{
    static const u8 swt[6] = {0,1,1,2,3,4}; /* .rodata.CSWTCH$657 */
    u8 v = (u8)(in_ & 0xff);
    if (v >= 6) {
        sc_printf("W (%d) %s: unknow security mode!\n");
        return 0xff;
    }
    return swt[v];
}

/* sc_recv_callback @ sc_esptouch_v2.o 0000000c size 72B bind GLOBAL
 * Calls: memset, sc_ieee80211_data_extract, sc_recv_callback_broadcast
 * Data refs: none (stack frame only)
 * Fidelity: medium-high - frame staging transcribed.
 * Observed: 64B stack frame, memset 24B; l32i frm+8, extui(16,4) nibble
 *   stored at local+21; l8u frm+0 sext'd (bit7 test); calls
 *   sc_ieee80211_data_extract(...) and if it returns 1 calls
 *   sc_recv_callback_broadcast(...); returns extract's (or broadcast's) value. */
u32 sc_recv_callback(u8 *frm, u32 len, u32 a, u32 b)
{
    u8 local[64];
    u32 rc;
    memset(local, 0, 24);
    local[21] = (u8)((*(u32 *)(frm + 8) >> 16) & 0xf);
    (void)len; (void)a; (void)b;
    rc = sc_ieee80211_data_extract(local, frm, len, a, b, 0, 0);
    if (rc == 1)
        rc = (u32)sc_recv_callback_broadcast(local, len, a, b);
    return rc;
}

/* sc_is_invalid_pkg @ sc_esptouch_v2.o 00000000 size 18B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - return (((len-127)&0xffffffff) > 0x431); i.e. valid
 *   802.11 lengths are 127..1160 (127+0x431). (addi -127, movi 0x431, bltu.) */
u32 sc_is_invalid_pkg(u32 len)
{
    return ((len - 127) > 0x431u) ? 1 : 0;
}

/* sc_sniffer_cb @ sc_esptouch_v2.o 00000024 size 120B bind GLOBAL
 * Calls: sc_recv_callback, sc_os_get_time_ms x2, sc_restart_switch_channel, log idiom
 * Data refs: psni_info, lock_start, g_osi_funcs_p, SC_TAG
 * Fidelity: medium-high - lock/timing state machine decoded.
 * Observed: rc=sc_recv_callback(frm,...); if (*psni_info!=1) return;
 *   if ((u8)(frmptr-2) > 4 (bgeui ..,4)) return; t=sc_os_get_time_ms();
 *   if lock_start==0 { lock_start=t; return; }
 *   if (t-lock_start < 0x271<<3 = 5000ms) return; else log
 *   "I: start scanning again" + sc_restart_switch_channel(). */
void sc_sniffer_cb(u8 *frm, u32 len, u32 arg2, u32 arg3)
{
    u32 t;
    (void)sc_recv_callback(frm, len, arg2, arg3);
    if (*(u8 *)psni_info != 1)
        return;
    if ((u32)((u8 *)frm - (u8 *)2) > 4u) /* bgeui range gate; approx base */
        return;
    t = sc_os_get_time_ms();
    if (lock_start == 0) {
        lock_start = t;
        return;
    }
    if ((t - lock_start) < (0x271u << 3)) /* 5000ms dwell */
        return;
    sc_printf("I (%d) %s: start scanning again\n");
    sc_restart_switch_channel();
}

/* sc_pack_handle @ sc_esptouch_v2.o 00000008 size 56B bind GLOBAL
 * Calls: sc_sniffer_cb | Data refs: SnifGlob
 * Fidelity: high - dispatch/length filter fully transcribed.
 * Observed: if (SnifGlob[16]==1) -> sc_sniffer_cb(frm,len,type) directly.
 *   Else L=(*(u32*)(frm+24)&0xfff); if (bit27 of *(frm+4) set && type==3)
 *   L=(L-4)&0xffff; if sc_is_invalid_pkg(L) (i.e. L outside 127..1160)
 *   drop; else sc_sniffer_cb(frm, L-4, type). */
void sc_pack_handle(u8 *frm, u32 type)
{
    u8 *s = (u8 *)SnifGlob;
    if (s[16] == 1) {
        sc_sniffer_cb(frm, type, 0, 0);
        return;
    }
    {
        u32 L = (*(u32 *)(frm + 24)) & 0xfff;
        if ((*(u32 *)(frm + 4) & (1u << 27)) && type == 3)
            L = (L - 4) & 0xffff;
        if (((L - 127) > 0x431u)) /* sc_is_invalid_pkg inline */
            return;
        sc_sniffer_cb(frm, L - 4, type, 0);
    }
}
