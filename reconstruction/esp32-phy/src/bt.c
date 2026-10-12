/* Reconstruction of bt.o (libbttestmode.a)
 * CU: bt.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 68 | funcdb functions: 2
 * Disasm: re/esp32-phy/disasm/libbttestmode/bt.rdis
 * Signatures tagged [dwarf-sig] (concrete DIE), [dwarf-sig-decl] (declaration-only DIE),
 * [dwarf-sig-base] (split $part$ clone; signature of base), or [inferred] (no DIE).
 * Fidelity: high = exact (stub or hand-verified); medium = structure + calls/MMIO verified,
 *   some expressions approximate; low = signature + header only, logic TODO.
 */
#include <stdint.h>
/* DWARF-derived fixed-width aliases (Xtensa LE, ILP32). bool is an 8-bit
 * unsigned type in this TU per DWARF (bool -> unsigned char). */
typedef unsigned char U8, u8, uint8, uint8_t, SDL_Octet, bool;
typedef signed char S8, s8, sint8, int8;
typedef unsigned short U16, u16, uint16, UnsignedShortInt;
typedef short S16, s16, sint16, ShortInt;
typedef unsigned int U32, u32, uint32, uint32_t, STATUS, CriticalType;
typedef int S32, s32, sint32, int32;
typedef unsigned long long U64, u64, uint64;
typedef long long S64, s64;

/* MMIO helpers (same convention as other reconstructed TUs). */
#define REG_READ(a) (*(volatile u32 *)(a))
#define REG_WRITE(a, v) (*(volatile u32 *)(a) = (v))

/* BTAutotest bt.c:54 @ bt.o size 2956B [dwarf-sig]
 * Calls: ets_isr_unmask, wifi_init_bt, bt_bb_init_cmplx, force_bt_mode, phy_printf, uart_div_modify, BT_testmode_tester, UartGetCmdLn, cmd_parse, strcmp, WifiTxStart, adctrig, set_tx_gain_table_bt, set_chan_freq_hw_init, register_chipv7_phy, chip_v7_rxmax_ext_ana, freq_offset_cfg, BT_tx_8m_enable, BT_tx_forever, BT_tx_packet_8m, BT_tx_packet, set_chan_freq_sw_start, BT_wait4tx_end_new, BT_rx_start, BT_loopback_master, BT_loopback_slave, BT_testmode_init, BT_test_mode_fill_tx_payload, BT_set_packet_attributes, BT_tx_sim_debug, BT_rx_sim_debug, BT_inquiry_test, BT_inquiry_scan_test, BT_con_tx_test, BT_page_scan_test, BT_page_test, BT_mac_rx_start_debug, BT_inq, BT_inq_scan, BT_page, BT_page_scan, BT_m_discon, BT_s_discon, BT_con_loopback_master, BT_con_loopback_slave, LE_start_tx, BT_con, prbs9_test, BT_gen_prbs9, BT_rx_prbs9_err_bits, BT_rx_ber, BT_rx_per, BT_rx_dump, BT_init_rx_filters, BT_mac_set_tx_link_type, BT_mac_set_rx_link_type, BT_tx_if_init, BT_mac_iqview_debug, noise_init_bt, BT_get_pwr, LE_rx_per, LE_rx_ber, le_dtm, RFChannelSel, WifiRxStart, FillTxPacket | Data refs: .rodata.str1.4, BT_con, BT_con_loopback_master, BT_con_loopback_slave, BT_con_tx_test, BT_gen_prbs9, BT_get_pwr, BT_init_rx_filters, BT_inq, BT_inq_scan, BT_inquiry_scan_test, BT_inquiry_test, BT_loopback_master, BT_loopback_slave, BT_m_discon, BT_mac_iqview_debug, BT_mac_rx_start_debug, BT_mac_set_rx_link_type, BT_mac_set_tx_link_type, BT_page, BT_page_scan, BT_page_scan_test, BT_page_test, BT_rx_ber, BT_rx_dump, BT_rx_per, BT_rx_prbs9_err_bits, BT_rx_sim_debug, BT_rx_start, BT_s_discon, BT_set_packet_attributes, BT_test_mode_fill_tx_payload, BT_testmode_init, BT_testmode_tester, BT_tx_8m_enable, BT_tx_forever, BT_tx_if_init, BT_tx_packet, BT_tx_packet_8m, BT_tx_sim_debug, BT_wait4tx_end_new, FillTxPacket, LE_rx_ber, LE_rx_per, LE_start_tx, RFChannelSel, UartGetCmdLn, WifiRxStart, WifiTxStart, adctrig, bt_bb_init_cmplx, bt_mode_wifibb, chip_v7_rxmax_ext_ana, cmd_parse, command, ets_isr_unmask, force_bt_mode, freq_offset_cfg, g_phyFuns, init_param_default, le_dtm, noise_init_bt, pString, para_array, para_num, phy_printf, prbs9_test, register_chipv7_phy, set_chan_freq_hw_init, set_chan_freq_sw_start, set_tx_gain_table_bt, strcmp, uart_div_modify, wifi_init_bt | MMIO: 0x60033c68
 * Fidelity: medium - dispatch prologue, exact command strings in exact order,
 *   exact per-branch callees/formats/lanes verified from disasm+relocs+rodata;
 *   UartGetCmdLn/cmd_parse plumbing, g_phyFuns hook slots and multi-word
 *   packing approximate */
void BTAutotest(void)
{
    /* DWARF locals: int result@l56, int i@l57, uint32 keycache_addr@l58, uint32 txdump_addr@l59, sint8[] array_temp_2@l60 */
    extern u8 command[];
    extern u32 para_array[], para_num;
    extern unsigned g_phyFuns[];
    int result, i;
    u32 keycache_addr, txdump_addr;
    s8 array_temp_2[64];
    u32 p0, p1, p2, p3, p4, p5, p6, p7, p8;
    ets_isr_unmask(32);
    wifi_init_bt();
    bt_bb_init_cmplx();
    force_bt_mode();
    phy_printf("\n\n\nForce BT\n");
    phy_printf("BT autotest!\n");
    uart_div_modify(0, 0x56c);
    BT_testmode_tester(0xdbbddaab, 0xfaab, 0x6b3211);
dispatch:
    if (!UartGetCmdLn(command, para_array, para_num))
        goto dispatch;
    result = cmd_parse(command, para_array, para_num);
    if (result != 1) {
        phy_printf(" cmd syntax error!\n");
        goto dispatch;
    }
    p0 = para_array[0]; p1 = para_array[1]; p2 = para_array[2];
    p3 = para_array[3]; p4 = para_array[4]; p5 = para_array[5];
    p6 = para_array[6]; p7 = para_array[7]; p8 = para_array[8];
    if (!strcmp(command, "WifiTxStart")) {
        if (p1 < 1)
            phy_printf(" wifi tx out\n");
        WifiTxStart(p0, p1, p2, p3, p4, p5);
        phy_printf(" Tx Over, tx_state:0x%x!\n", REG_READ(0x60033c68u) & 0xffu);
        goto dispatch;
    }
    if (!strcmp(command, "adctrig")) {
        adctrig(p0, p1, p2, p3);
        goto dispatch;
    }
    if (!strcmp(command, "bt_tx_gain")) {
        i = (s8)((u8)p0);
        set_tx_gain_table_bt(i);
        phy_printf("bt_tx_gain, %ddB\n", i);
        goto dispatch;
    }
    if (!strcmp(command, "hoppe_init")) {
        set_chan_freq_hw_init((u8)p0, (u16)(p2 >> 0), (u8)p1);
        phy_printf("hoppe init!\n");
        goto dispatch;
    }
    if (!strcmp(command, "phy_init")) {
        register_chipv7_phy(p0);
        phy_printf("phy_init, bt_mode_wifibb=%d\n", p0);
        goto dispatch;
    }
    if (!strcmp(command, "rxmax_ext")) {
        chip_v7_rxmax_ext_ana(p0);
        phy_printf("rxmax_ext config done!\n");
        goto dispatch;
    }
    if (!strcmp(command, "freq_offset_cfg")) {
        phy_printf("freq offset config!\n");
        freq_offset_cfg(p0, p1, p2, p3, p4, p5, p6, p7, p8, p0, p1, p2);
        goto dispatch;
    }
    if (!strcmp(command, "BT_tx_cfg")) {
        phy_printf("BT tx config!\n");
        BT_tx_8m_enable(p0);
        goto dispatch;
    }
    if (!strcmp(command, "BT_tx_packet")) {
        phy_printf(" BT_tx_%dm_packet!\n", p6);
        if (p0 == 1) {
            BT_tx_forever((u16)p3);
        } else if (para_array[10] == 1) {
            BT_tx_packet_8m(p1, p2, p3, p4, p5, p6, p7, p8, para_array[9]);
        } else {
            BT_tx_packet(p0, p1, p2, p3, p4, p5);
        }
        phy_printf("BT_tx_1m_packet stop!\n");
        goto dispatch;
    }
    if (!strcmp(command, "bt_set_freq")) {
        set_chan_freq_sw_start(0, p0);
        phy_printf("bt_set_freq %d\n", p0);
        goto dispatch;
    }
    if (!strcmp(command, "BT_tx_packet_stop")) {
        BT_wait4tx_end_new();
        phy_printf("BT_tx_%dm_packet stop!\n", p0);
        goto dispatch;
    }
    if (!strcmp(command, "BT_rx_start")) {
        BT_rx_start((u16)p0, (u16)p1, (u16)p2, (u16)p3, (u16)p4);
        goto dispatch;
    }
    if (!strcmp(command, "BT_mac_loopback_master")) {
        BT_loopback_master(p0, (u16)p1, (u16)p2, p3, p4);
        goto dispatch;
    }
    if (!strcmp(command, "BT_mac_loopback_slave")) {
        BT_loopback_slave(p0, p1, p2, (u16)p3, (u16)p4, p5);
        goto dispatch;
    }
    if (!strcmp(command, "BT_testmode_init")) {
        BT_testmode_init((u16)p0, (u16)p1, p2);
        phy_printf("BT testmode init!\n");
        goto dispatch;
    }
    if (!strcmp(command, "BT_test_mode_fill_tx_payload")) {
        BT_test_mode_fill_tx_payload(p0, p1, p2, p3, p4);
        phy_printf("BT fill tx payload!\n");
        goto dispatch;
    }
    if (!strcmp(command, "BT_set_packet_attributes")) {
        BT_set_packet_attributes(p0, p1, p2, p3, p4, p5);
        phy_printf("BT set packet attributes!\n");
        goto dispatch;
    }
    if (!strcmp(command, "BT_tx_sim_debug")) {
        result = BT_tx_sim_debug(0);
        phy_printf("%d\n", result);
        goto dispatch;
    }
    if (!strcmp(command, "BT_rx_sim_debug")) {
        phy_printf(" \n");
        BT_rx_sim_debug();
        goto dispatch;
    }
    if (!strcmp(command, "BT_inquiry_test")) {
        phy_printf("BT_inquiry_test! \n");
        BT_inquiry_test(p0, p1);
        goto dispatch;
    }
    if (!strcmp(command, "BT_inquiry_scan_test")) {
        phy_printf("BT_inquiry_scan_test! \n");
        BT_inquiry_scan_test(p0, p1);
        goto dispatch;
    }
    if (!strcmp(command, "BT_con_tx_test")) {
        phy_printf("BT_con_tx_test! \n");
        BT_con_tx_test(p0, p1, p2, p3, p4, p5);
        goto dispatch;
    }
    if (!strcmp(command, "BT_page_scan_test")) {
        BT_page_scan_test(p0, p1, p2);
        goto dispatch;
    }
    if (!strcmp(command, "BT_page_test")) {
        BT_page_test(p0, p1, p2);
        goto dispatch;
    }
    if (!strcmp(command, "BT_mac_rx_start_debug")) {
        phy_printf(" BT rx debug start!\n");
        BT_mac_rx_start_debug(p0, p1);
        goto dispatch;
    }
    if (!strcmp(command, "BT_inq")) {
        phy_printf("inquiry start!\n");
        BT_inq(p0);
        goto dispatch;
    }
    if (!strcmp(command, "BT_inq_scan")) {
        phy_printf("inquiry scan start!\n");
        BT_inq_scan(p0);
        goto dispatch;
    }
    if (!strcmp(command, "BT_page")) {
        BT_page(p0, p1, p2, p3, p4, p5);
        goto dispatch;
    }
    if (!strcmp(command, "BT_page_scan")) {
        BT_page_scan(p0, p1);
        goto dispatch;
    }
    if (!strcmp(command, "BT_m_discon")) {
        BT_m_discon();
        phy_printf("M_discon!\n");
        goto dispatch;
    }
    if (!strcmp(command, "BT_s_discon")) {
        BT_s_discon(p0);
        phy_printf("S_discon!\n");
        goto dispatch;
    }
    if (!strcmp(command, "BT_con_loopback_master")) {
        BT_con_loopback_master(p0);
        goto dispatch;
    }
    if (!strcmp(command, "BT_con_loopback_slave")) {
        phy_printf("0\n");
        BT_con_loopback_slave(p0, p1, p2, p3);
        goto dispatch;
    }
    if (!strcmp(command, "LE_start_tx")) {
        phy_printf("TX LE packet!\n");
        LE_start_tx(p0, p1, p2);
        goto dispatch;
    }
    if (!strcmp(command, "BT_con")) {
        BT_con(p0);
        phy_printf("BT_con!\n");
        goto dispatch;
    }
    if (!strcmp(command, "prbs9_test")) {
        prbs9_test();
        goto dispatch;
    }
    if (!strcmp(command, "BT_gen_prbs9")) {
        BT_gen_prbs9();
        phy_printf("GEN PRBS9 DONE\n");
        goto dispatch;
    }
    if (!strcmp(command, "BT_rx_prbs9_err_bits")) {
        BT_rx_prbs9_err_bits();
        goto dispatch;
    }
    if (!strcmp(command, "BT_rx_ber")) {
        BT_rx_ber(p0, p1, p2, p3, p4);
        goto dispatch;
    }
    if (!strcmp(command, "BT_rx_per")) {
        BT_rx_per(p0, p1);
        goto dispatch;
    }
    if (!strcmp(command, "BT_rx_dump")) {
        BT_rx_dump(p0, p1);
        goto dispatch;
    }
    if (!strcmp(command, "BT_rx_noise")) {
        BT_init_rx_filters(59);
        BT_mac_set_tx_link_type(3, command[0]);
        BT_mac_set_rx_link_type(3, command[0]);
        BT_tx_8m_enable(63);
        BT_tx_if_init(0x14a, 0x3e8, 200, 1);
        BT_mac_iqview_debug(1);
        set_chan_freq_sw_start(command[0], p0 + 2);
        noise_init_bt();
        BT_get_pwr();
        phy_printf("%x %x %x %x\n", p0, p1, p2, p3);
        goto dispatch;
    }
    if (!strcmp(command, "LE_rx_per")) {
        LE_rx_per(p0, 1);
        goto dispatch;
    }
    if (!strcmp(command, "LE_rx_ber")) {
        LE_rx_ber(p0, 1, p1);
        goto dispatch;
    }
    if (!strcmp(command, "LE_DTM")) {
        phy_printf("LE_DTM!\n");
        le_dtm();
        goto dispatch;
    }
    if (!strcmp(command, "txtone")) {
        phy_printf(" wifi single carrier out\n");
        goto dispatch;
    }
    if (!strcmp(command, "stoptone")) {
        phy_printf(" Wifi Tx Tone Over!\n");
        goto dispatch;
    }
    if (!strcmp(command, "RFChannelSel")) {
        RFChannelSel((s8)p0, (s8)p1);
        phy_printf(" RF channel select as %d %d\n", p0, p1);
        goto dispatch;
    }
    if (!strcmp(command, "WifiRxStart")) {
        phy_printf("wifi rx in\n");
        WifiRxStart(p0);
        goto dispatch;
    }
    if (!strcmp(command, "FillTxPacket")) {
        FillTxPacket(p0, p1, p2, p3, p4, p5, p6, p7, p8, para_array[9], para_array[10], para_array[11]);
        phy_printf("Fill Tx Packet OK!\n");
        goto dispatch;
    }
    if (!strcmp(command, "pbus_debugmode")) {
        ((void (*)())((u32 *)g_phyFuns[0])[48])();
        phy_printf("pbus set debugmode ok!\n");
        goto dispatch;
    }
    if (!strcmp(command, "pbus_workmode")) {
        ((void (*)())((u32 *)g_phyFuns[0])[49])();
        phy_printf("pbus set workmode ok!\n");
        goto dispatch;
    }
    if (!strcmp(command, "pbus")) {
        ((void (*)())((u32 *)g_phyFuns[0])[46])((u8)p0, (u8)p1, (u16)p2);
        phy_printf("pbus set ok!\n");
        goto dispatch;
    }
    if (!strcmp(command, "pbus_rd")) {
        result = ((int (*)())((u32 *)g_phyFuns[0])[47])((u8)p0, (u8)p1);
        phy_printf("0x%x\n", result);
        goto dispatch;
    }
    if (!strcmp(command, "rd")) {
        phy_printf("0x%x\n", REG_READ(p0));
        goto dispatch;
    }
    if (!strcmp(command, "wr")) {
        REG_WRITE(p0, p1);
        phy_printf("0x%x\n", p0);
        goto dispatch;
    }
    if (!strcmp(command, "sm")) {
        REG_WRITE(p0, REG_READ(p0) | (1u << (p1 & 31u)));
        phy_printf("reg 0x%x readback is 0x%x\n", p0, REG_READ(p0));
        goto dispatch;
    }
    if (!strcmp(command, "cm")) {
        phy_printf("reg 0x%x readback is 0x%x\n", p0, REG_READ(p0));
        goto dispatch;
    }
    if (!strcmp(command, "gb")) {
        phy_printf("0x%x\n", (REG_READ(p0) >> (p1 & 31u)) & 0xffu);
        goto dispatch;
    }
    if (!strcmp(command, "RdMem")) {
        for (i = (int)p0; i < (int)(p0 + p1); i += 4)
            phy_printf("0x%x ", REG_READ((u32)i));
        phy_printf("\n");
        goto dispatch;
    }
    if (!strcmp(command, "ri")) {
        result = ((int (*)())((u32 *)g_phyFuns[0])[38])((u8)p0, (u8)p1, (u8)p2);
        phy_printf("0x%x\n", result);
        goto dispatch;
    }
    if (!strcmp(command, "wi")) {
        ((void (*)())((u32 *)g_phyFuns[0])[40])((u8)p0, (u8)p1, (u8)p2, (u8)p3);
        phy_printf("write ok!\n");
        goto dispatch;
    }
    if (!strcmp(command, "wim")) {
        ((void (*)())((u32 *)g_phyFuns[0])[42])((u8)p0, (u8)p1, (u8)p2, (u8)p3, (u8)p4, (u8)p5);
        phy_printf("write ok!\n");
        goto dispatch;
    }
    if (!strcmp(command, "rim")) {
        phy_printf("0x%x\n", p0);
        phy_printf("cmd not exist!\n");
        goto dispatch;
    }
    phy_printf("cmd not exist!\n");
    goto dispatch;
}

/* BT_hoppe bt.c:32 @ bt.o size 50B [dwarf-sig]
 * Calls: phy_printf, set_chan_freq_sw_start | Data refs: .rodata.str1.4, phy_printf, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_hoppe(void)
{
    /* DWARF locals: u32 i@l33 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt.rdis
     * function <BT_hoppe> (18 insns) + DWARF line rows for bt.c:32.
     * Ordered callee relocs: phy_printf, set_chan_freq_sw_start.
     */
}

/* Undefined refs (73): BT_con, BT_con_loopback_master, BT_con_loopback_slave, BT_con_tx_test, BT_gen_prbs9, BT_get_pwr, BT_init_rx_filters, BT_inq, BT_inq_scan, BT_inquiry_scan_test, BT_inquiry_test, BT_loopback_master, BT_loopback_slave, BT_m_discon, BT_mac_iqview_debug, BT_mac_rx_start_debug, BT_mac_set_rx_link_type, BT_mac_set_tx_link_type, BT_page, BT_page_scan, BT_page_scan_test, BT_page_test, BT_rx_ber, BT_rx_dump, BT_rx_per, BT_rx_prbs9_err_bits, BT_rx_sim_debug, BT_rx_start, BT_s_discon, BT_set_packet_attributes, BT_test_mode_fill_tx_payload, BT_testmode_init, BT_testmode_tester, BT_tx_8m_enable, BT_tx_forever, BT_tx_if_init, BT_tx_packet, BT_tx_packet_8m, BT_tx_sim_debug, BT_wait4tx_end_new, FillTxPacket, LE_rx_ber, LE_rx_per, LE_start_tx, RFChannelSel, UartGetCmdLn, WifiRxStart, WifiTxStart, adctrig, bt_bb_init_cmplx, bt_mode_wifibb, chip_v7_rxmax_ext_ana, cmd_parse, command, ets_isr_unmask, force_bt_mode, freq_offset_cfg, g_phyFuns, init_param_default, le_dtm... */