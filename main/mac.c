#include "esp_wifi.h" // included for the definition of the wifi_promiscuous_pkt_t struct
#include "esp_mac.h"  // included for the MAC2STR macro
#include "esp_log.h"
#include "esp_timer.h"

#include "hardware.h"
#include "80211.h"
#include "mac.h"
#include "proprietary.h"

#include <string.h>

static char* TAG = "mac.c";
static tx_func* tx = NULL;
static QueueHandle_t reception_queue = NULL;

static uint8_t to_ap_auth_frame[] = {
    0xb0, 0x00, 0x00, 0x00,
    0x4e, 0xed, 0xfb, 0x35, 0x22, 0xa8, // receiver addr
    0x00, 0x23, 0x45, 0x67, 0x89, 0xab, // transmitter addr
    0x4e, 0xed, 0xfb, 0x35, 0x22, 0xa8, // bssid
    0x00, 0x00, // sequence control
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0, 0, 0, 0 /*FCS*/};

static uint8_t to_ap_assoc_frame[] = {
    0x00, 0x00, 0x00, 0x00,
    0x4e, 0xed, 0xfb, 0x35, 0x22, 0xa8, // receiver addr
    0x00, 0x23, 0x45, 0x67, 0x89, 0xab, // transmitter addr
    0x4e, 0xed, 0xfb, 0x35, 0x22, 0xa8, // bssid
    0x00, 0x00, // sequence control
    0x11, 0x00, 0x0a, 0x00, // Fixed parameters
    0x00, 0x08, 0x6d, 0x65, 0x73, 0x68, 0x74, 0x65, 0x73, 0x74, // SSID
    0x01, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,  // Supported rates
    0, 0, 0, 0 /*FCS*/};

static uint8_t to_ap_data_frame[] = {
    0x08, 0x01, 0x00, 0x00,
    0x4e, 0xed, 0xfb, 0x35, 0x22, 0xa8, // receiver addr
    0x00, 0x23, 0x45, 0x67, 0x89, 0xab, // transmitter
    0x84, 0x2b, 0x2b, 0x4f, 0x89, 0x4f, // destination
    0x00, 0x00, // sequence control
    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x29, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x34, 0xba, 0x0a, 0x00, 0x32, 0x02, 0x0a, 0x00, 0x00, 0x08, 0xea, 0x61, 0x0d, 0x05, 0x00, 0x15, 0x46, 0x64, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a,
    0, 0, 0, 0 /*FCS*/};

// Gets called with a packet that was received. This function does not need to free the memory of the packet,
//  but the packet will become invalid after this function returns. If you need any data from the packet,
//  better copy it before returning!
// Please avoid doing heavy processing here: it's not in an interrupt, but if this function is not fast enough,
// the RX queue that is used to pass packets to this function might overflow and drop packets.
void open_mac_rx_callback(wifi_promiscuous_pkt_t* packet) {
    mac80211_frame* p = (mac80211_frame*) packet->payload;

    // fuck beacon frames, all my homies hate beacon frames
    if (p->frame_control.type == IEEE80211_TYPE_MGT && p->frame_control.sub_type == IEEE80211_TYPE_MGT_SUBTYPE_BEACON) return;

    // check that receiver mac address matches our mac address or is broadcast
    if ((memcmp(module_mac_addr, p->receiver_address, 6))
     && (memcmp(BROADCAST_MAC, p->receiver_address, 6))) {
        // We're not interested in this packet, return early to avoid having to copy it further to the networking stack
        ESP_LOGD(TAG, "Discarding packet from "MACSTR" to "MACSTR, MAC2STR(p->transmitter_address), MAC2STR(p->receiver_address));
        return;
    }
    ESP_LOGI(TAG, "Accepted: from "MACSTR" to "MACSTR" type=%d, subtype=%d from_ds=%d to_ds=%d", MAC2STR(p->transmitter_address), MAC2STR(p->receiver_address), p->frame_control.type, p->frame_control.sub_type, p->frame_control.from_ds, p->frame_control.to_ds);

    if (!reception_queue) {
        ESP_LOGI(TAG, "Received, but queue does not exist yet");
        return;
    }
    // 28 is size of rx_ctrl, 4 is size of FCS (which we don't need)
    wifi_promiscuous_pkt_t* packet_queue_copy = malloc(packet->rx_ctrl.sig_len + 28 - 4);
    memcpy(packet_queue_copy, packet, packet->rx_ctrl.sig_len + 28 - 4);

    if (!(xQueueSendToBack(reception_queue, &packet_queue_copy, 0))) {
        ESP_LOGW(TAG, "MAC RX queue full!");
    }
}

// This function will get called exactly once, with as argument a function (`bool tx_func(uint8_t* packet, uint32_t len)`).
// The function that is passed will TX packets. If it returned `true`, that means that the packet was sent. If false,
//  you'll need to call the function again.
void open_mac_tx_func_callback(tx_func* t) {
    tx = t;
}

void mac_task(void* pvParameters) {
    ESP_LOGI(TAG, "Starting mac_task, running on %d", xPortGetCoreID());

    reception_queue = xQueueCreate(10, sizeof(wifi_promiscuous_pkt_t*));
    assert(reception_queue);

    openmac_sta_state_t sta_state = IDLE;
    uint64_t last_transmission_us = esp_timer_get_time();

    while (true) {
        wifi_promiscuous_pkt_t* packet;
        if(xQueueReceive(reception_queue, &packet, 10)) {          
            mac80211_frame* p = (mac80211_frame*) packet->payload;

            if (!(p->frame_control.type == IEEE80211_TYPE_MGT && p->frame_control.sub_type == IEEE80211_TYPE_MGT_SUBTYPE_BEACON)) {
                // Print all non-beacon packets
                ESP_LOG_BUFFER_HEXDUMP("packet-content", packet->payload, packet->rx_ctrl.sig_len - 4, ESP_LOG_INFO);  
            }

            switch (sta_state)
            {
            case IDLE: // idle, wait for authenticate packet
                if (p->frame_control.type == IEEE80211_TYPE_MGT && p->frame_control.sub_type == IEEE80211_TYPE_MGT_SUBTYPE_AUTHENTICATION) {
                    // TODO check that authentication succeeded
                    // For now, assume it's fine
                    ESP_LOGW(TAG, "Authentication received from="MACSTR" to= "MACSTR, MAC2STR(p->transmitter_address), MAC2STR(p->receiver_address));
                    sta_state = AUTHENTICATED;
                    last_transmission_us = 0;
                }
                break;
            case AUTHENTICATED: // authenticated, wait for association response packet
                if (p->frame_control.type == IEEE80211_TYPE_MGT && p->frame_control.sub_type == IEEE80211_TYPE_MGT_SUBTYPE_ASSOCIATION_RESP) {
                    // TODO check that association succeeded
                    // For now, assume it's fine
                    ESP_LOGW(TAG, "Association response received from="MACSTR" to= "MACSTR, MAC2STR(p->transmitter_address), MAC2STR(p->receiver_address));
                    sta_state = ASSOCIATED;
                    last_transmission_us = 0;
                }
                break;
            case ASSOCIATED: // associated
                break;
            default:
                break;
            }
            free(packet);
        }
        
        // don't transmit too fast
        if (esp_timer_get_time() - last_transmission_us < 1000*1000) continue;

        // don't transmit if we don't know how to
        if (!tx) {
            ESP_LOGW(TAG, "no transmit function yet");
            continue;
        };

        switch (sta_state)
        {
        case IDLE:
            ESP_LOGI(TAG, "Sending authentication frame!");
            tx(to_ap_auth_frame, sizeof(to_ap_auth_frame));
            break;
        case AUTHENTICATED:
            ESP_LOGI(TAG, "Sending association request frame!");
            tx(to_ap_assoc_frame, sizeof(to_ap_assoc_frame));
            break;
        case ASSOCIATED:
            ESP_LOGI(TAG, "Sending data frame");
            tx(to_ap_data_frame, sizeof(to_ap_data_frame));
            break;
        default:
            break;
        }
        last_transmission_us = esp_timer_get_time();
    }
}