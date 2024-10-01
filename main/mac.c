#include "esp_wifi.h" // included for the definition of the wifi_promiscuous_pkt_t struct
#include "esp_mac.h"  // included for the MAC2STR macro
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_netif_defaults.h"

#include "hardware.h"
#include "80211.h"
#include "mac.h"
#include "proprietary.h"

#include <string.h>

static char* TAG = "mac.c";
static tx_func* tx = NULL;
static QueueHandle_t reception_queue = NULL;

typedef struct openmac_netif_driver* openmac_netif_driver_t;

typedef struct openmac_netif_driver {
    esp_netif_driver_base_t base;
}* openmac_netif_driver_t;

static bool receive_task_is_running = true;
static esp_netif_t *netif_openmac = NULL;

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

static esp_err_t openmac_netif_transmit(void *h, void *buffer, size_t len)
{
    uint8_t* eth_data = (uint8_t*) buffer;
    ESP_LOGI("netif-tx", "Going to transmit a data packet: to "MACSTR" from "MACSTR" type=%02x%02x", MAC2STR(&eth_data[0]), MAC2STR(&eth_data[6]), eth_data[12], eth_data[13]);
    // TODO reimplement this to pass through the rust stack
    return ESP_OK;
}
static esp_err_t openmac_netif_transmit_wrap(void *h, void *buffer, size_t len, void *netstack_buf)
{
    return openmac_netif_transmit(h, buffer, len);
}


// Free RX buffer (not used as the buffer is static)
// TODO ^ is this true?
static void openmac_free(void *h, void* buffer)
{
    ESP_LOGI(TAG, "Free-ing RX'd packet %p", buffer);
    free(buffer);
}

static esp_err_t openmac_driver_start(esp_netif_t * esp_netif, void * args)
{
    openmac_netif_driver_t driver = args;
    driver->base.netif = esp_netif;
    esp_netif_driver_ifconfig_t driver_ifconfig = {
            .handle =  driver,
            .transmit = openmac_netif_transmit,
            .transmit_wrap = openmac_netif_transmit_wrap,
            .driver_free_rx_buffer = openmac_free
    };

    return esp_netif_set_driver_config(esp_netif, &driver_ifconfig);
}


openmac_netif_driver_t openmac_create_if_driver()
{
    openmac_netif_driver_t driver = calloc(1, sizeof(struct openmac_netif_driver));
    if (driver == NULL) {
        ESP_LOGE(TAG, "No memory to create a wifi interface handle");
        return NULL;
    }
    driver->base.post_attach = openmac_driver_start;
    
    // TODO fix this
    if (!receive_task_is_running) {
        receive_task_is_running = true;
    }
    return driver;
}

esp_err_t openmac_netif_start()
{
    esp_netif_inherent_config_t base_cfg = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
    base_cfg.if_desc = "openmac";
    // base_cfg.get_ip_event = NULL;
    // base_cfg.lost_ip_event = NULL;

    esp_netif_config_t cfg = {
            .base = &base_cfg,
            .driver = NULL,
            .stack = ESP_NETIF_NETSTACK_DEFAULT_WIFI_STA };
    netif_openmac = esp_netif_new(&cfg);
    assert(netif_openmac);

    openmac_netif_driver_t driver = openmac_create_if_driver();
    if (driver == NULL) {
        ESP_LOGE(TAG, "Failed to create wifi interface handle");
        return ESP_FAIL;
    }
    esp_netif_attach(netif_openmac, driver);
    esp_netif_set_hostname(netif_openmac, "esp32-open-mac");
    esp_netif_set_mac(netif_openmac, module_mac_addr);
    esp_netif_action_start(netif_openmac, NULL, 0, NULL);
    return ESP_OK;
}