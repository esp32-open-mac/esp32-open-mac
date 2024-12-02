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

#include "80211_mac_interface.h"

#include <string.h>

static char* TAG = "mac.c";

typedef struct openmac_netif_driver* openmac_netif_driver_t;

typedef struct openmac_netif_driver {
    esp_netif_driver_base_t base;
}* openmac_netif_driver_t;

static esp_netif_t *netif_openmac_sta = NULL;

static esp_err_t openmac_netif_transmit(void *h, void *buffer, size_t len)
{
    uint8_t* eth_data = (uint8_t*) buffer;
    ESP_LOGI("netif-tx", "Going to transmit a data packet: to "MACSTR" from "MACSTR" type=%02x%02x", MAC2STR(&eth_data[0]), MAC2STR(&eth_data[6]), eth_data[12], eth_data[13]);
    c_transmit_data_frame(buffer, len);
    return ESP_OK;
}

static esp_err_t openmac_netif_transmit_wrap(void *h, void *buffer, size_t len, void *netstack_buf)
{
    return openmac_netif_transmit(h, buffer, len);
}


void openmac_netif_up() {
    esp_netif_action_connected(netif_openmac_sta, NULL, 0, NULL);
}

void openmac_netif_down() {
    esp_netif_action_disconnected(netif_openmac_sta, NULL, 0, NULL);
}

// Put Ethernet-formatted frame in MAC stack; does not take ownership of the buffer: after the function returns, you can delete/reuse it.
void openmac_netif_receive(void* buffer, size_t len) {
    assert(buffer != NULL);
    esp_netif_receive(netif_openmac_sta, buffer, len, buffer);
}

// Free RX buffer
static void openmac_free(void *h, void* buffer)
{
    c_recycle_mac_rx_frame(buffer);
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
    
    return driver;
}

esp_err_t openmac_netif_start()
{
    esp_netif_inherent_config_t base_cfg_sta = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
    base_cfg_sta.if_desc = "openmac_sta";

    esp_netif_config_t cfg_sta = {
            .base = &base_cfg_sta,
            .driver = NULL,
            .stack = ESP_NETIF_NETSTACK_DEFAULT_WIFI_STA };
    netif_openmac_sta = esp_netif_new(&cfg_sta);
    assert(netif_openmac_sta);

    openmac_netif_driver_t driver = openmac_create_if_driver();
    if (driver == NULL) {
        ESP_LOGE(TAG, "Failed to create wifi interface handle");
        return ESP_FAIL;
    }
    esp_netif_attach(netif_openmac_sta, driver);
    esp_netif_set_hostname(netif_openmac_sta, "esp32-open-mac");
    esp_netif_set_mac(netif_openmac_sta, module_mac_addr);
    esp_netif_action_start(netif_openmac_sta, NULL, 0, NULL);
    return ESP_OK;
}