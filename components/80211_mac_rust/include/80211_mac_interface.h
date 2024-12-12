#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Number of virtual interfaces the hardware supports
// See https://esp32-open-mac.be/posts/0008-rx-filter/
#define NUM_VIRTUAL_INTERFACES (2)

#define CONFIG_IDF_TARGET_ESP32 1

/** @brief Received packet radio metadata header, this is the common header at the beginning of all promiscuous mode RX callback buffers */
typedef struct {
    signed rssi:8;                /**< Received Signal Strength Indicator(RSSI) of packet. unit: dBm */
    unsigned rate:5;              /**< PHY rate encoding of the packet. Only valid for non HT(11bg) packet */
    unsigned :1;                  /**< reserved */
    unsigned sig_mode:2;          /**< 0: non HT(11bg) packet; 1: HT(11n) packet; 3: VHT(11ac) packet */
    unsigned :8;                  /**< reserved */
    unsigned :4;
    unsigned filter_match:2;
    unsigned :2;
    unsigned mcs:7;               /**< Modulation Coding Scheme. If is HT(11n) packet, shows the modulation, range from 0 to 76(MSC0 ~ MCS76) */
    unsigned cwb:1;               /**< Channel Bandwidth of the packet. 0: 20MHz; 1: 40MHz */
    unsigned :16;                 /**< reserved */
    unsigned smoothing:1;         /**< reserved */
    unsigned not_sounding:1;      /**< reserved */
    unsigned :1;                  /**< reserved */
    unsigned aggregation:1;       /**< Aggregation. 0: MPDU packet; 1: AMPDU packet */
    unsigned stbc:2;              /**< Space Time Block Code(STBC). 0: non STBC packet; 1: STBC packet */
    unsigned fec_coding:1;        /**< Flag is set for 11n packets which are LDPC */
    unsigned sgi:1;               /**< Short Guide Interval(SGI). 0: Long GI; 1: Short GI */
#if CONFIG_IDF_TARGET_ESP32
    signed noise_floor:8;         /**< noise floor of Radio Frequency Module(RF). unit: dBm*/
#elif CONFIG_IDF_TARGET_ESP32S2 || CONFIG_IDF_TARGET_ESP32S3 || CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32C2
    unsigned :8;                  /**< reserved */
#endif
    unsigned ampdu_cnt:8;         /**< ampdu cnt */
    unsigned channel:4;           /**< primary channel on which this packet is received */
    unsigned secondary_channel:4; /**< secondary channel on which this packet is received. 0: none; 1: above; 2: below */
    unsigned :8;                  /**< reserved */
    unsigned timestamp:32;        /**< timestamp. The local time when this packet is received. It is precise only if modem sleep or light sleep is not enabled. unit: microsecond */
    unsigned :32;                 /**< reserved */
#if CONFIG_IDF_TARGET_ESP32S2
    unsigned :32;                 /**< reserved */
#elif CONFIG_IDF_TARGET_ESP32S3 || CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32C2
    signed noise_floor:8;         /**< noise floor of Radio Frequency Module(RF). unit: dBm*/
    unsigned :24;                 /**< reserved */
    unsigned :32;                 /**< reserved */
#endif
    unsigned :31;                 /**< reserved */
    unsigned ant:1;               /**< antenna number from which this packet is received. 0: WiFi antenna 0; 1: WiFi antenna 1 */
#if CONFIG_IDF_TARGET_ESP32S2
    signed noise_floor:8;         /**< noise floor of Radio Frequency Module(RF). unit: dBm*/
    unsigned :24;                 /**< reserved */
#elif CONFIG_IDF_TARGET_ESP32S3 || CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32C2
    unsigned :32;                 /**< reserved */
    unsigned :32;                 /**< reserved */
    unsigned :32;                 /**< reserved */
#endif
    unsigned sig_len:12;          /**< length of packet including Frame Check Sequence(FCS) */
    unsigned :12;                 /**< reserved */
    unsigned rx_state:8;          /**< state of the packet. 0: no error; others: error numbers which are not public */
} wifi_pkt_rx_ctrl_openmac_t;

/** @brief Payload passed to 'buf' parameter of promiscuous mode RX callback.
 */
typedef struct {
    wifi_pkt_rx_ctrl_openmac_t rx_ctrl; /**< metadata header */
    uint8_t payload[0];       /**< Data or management payload. Length of payload is described by rx_ctrl.sig_len. Type of content determined by packet type argument of callback. */
} wifi_promiscuous_pkt_openmac_t;

typedef struct __attribute__((packed)) dma_list_item { // TODO replace the fields with the names from the dma struct in the ESP IDF
	uint16_t size : 12;
	uint16_t length : 12;
	uint8_t _unknown : 6;
	uint8_t has_data : 1;
	uint8_t owner : 1;
	wifi_promiscuous_pkt_openmac_t* packet;
	struct dma_list_item* next;
} dma_list_item;

typedef enum {
    STA_1_MAC_INTERFACE_TYPE,
    STA_2_MAC_INTERFACE_TYPE,
    AP_1_MAC_INTERFACE_TYPE,
    AP_2_MAC_INTERFACE_TYPE,
} rs_mac_interface_type_t;

typedef enum {
    EVENT_TYPE_MAC_TX_DATA_FRAME,
    EVENT_TYPE_MAC_FREE_RX_DATA,
    EVENT_TYPE_PHY_RX_DATA,
} rs_event_type_t;

typedef struct {
    uint8_t* payload;
    size_t payload_length; // modifiable, contains the amount of valid data in payload
    size_t payload_size; // not modifiable, contains at all times the actual length of payload buffer
    uint32_t rate;
} rs_smart_frame_t; // has a frame, and the metadata (rate, length, ...)


/**
 * This is essentially a handle, so don't generate copy trait
 * <div rustbindgen nocopy></div>
 */
typedef struct {
  uint8_t* payload;
  size_t payload_length;
  size_t payload_size;
  uint32_t rate;
  int32_t rssi;
  // ...
} rs_rx_frame_t;

/*Called from the Rust MAC stack, gets the next event*/
bool rs_get_next_mac_event_raw(uint32_t ms_to_wait, rs_event_type_t* event_type, void** ptr, size_t* len);

/*Called from the Rust MAC stack, to obtain a smart frame, which can then be filled in*/
rs_smart_frame_t* rs_get_smart_frame(size_t size_hint);

/*Called from the Rust MAC stack, to TX a smart frame previously obtained via rs_get_smart_frame*/
void rs_tx_smart_frame(rs_smart_frame_t* frame);

/*Called from the Rust MAC stack, to pass a data frame to the IP stack. Expects the frame to be in Ethernet format. Does not take ownership of the data*/
void rs_rx_mac_frame(rs_mac_interface_type_t interface, uint8_t* frame, size_t len);

void rs_recycle_dma_item(dma_list_item* item);


void rs_mark_iface_up(rs_mac_interface_type_t interface);
void rs_mark_iface_down(rs_mac_interface_type_t interface);

/*
  Called from the hardware stack to recycle a smart frame after it was sent
*/
void c_recycle_tx_smart_frame(rs_smart_frame_t* frame);


void rust_mac_task();
void c_mac_task();
void c_hand_rx_to_mac_stack();

int64_t rs_get_time_us();

void c_transmit_data_frame(rs_mac_interface_type_t interface, uint8_t* frame, size_t len);
void rs_recycle_mac_tx_data(uint8_t* frame);

uint8_t* rs_get_mac_rx_frame(size_t size_required);
void c_recycle_mac_rx_frame(uint8_t* buffer);

void rs_change_channel(uint8_t channel);
void rs_filters_set_scanning(uint8_t interface, const uint8_t* own_addr);
void rs_filters_set_client_with_bssid(uint8_t interface, const uint8_t* own_addr, const uint8_t* bssid);
void rs_filters_set_ap_mode(uint8_t interface, const uint8_t* bssid);

