#include "esp_wifi.h" // included for the definition of the wifi_promiscuous_pkt_t struct
#include "esp_mac.h"  // included for the MAC2STR macro
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_netif_defaults.h"

#include "hardware.h"
#include "mac.h"
#include "proprietary.h"

#include "80211_mac_interface.h"

#include <string.h>

static char* TAG = "mac.c";

typedef struct openmac_netif_driver {
    esp_netif_driver_base_t base;
    rs_mac_interface_type_t interface_type;
} openmac_netif_driver_t;

static openmac_netif_driver_t* active_interfaces[NUM_VIRTUAL_INTERFACES] = {0};

static esp_err_t openmac_netif_transmit(void *h, void *buffer, size_t len)
{
    openmac_netif_driver_t* driver = (openmac_netif_driver_t*)h;

    for (int i = 0; i < NUM_VIRTUAL_INTERFACES; i++) {
        if (active_interfaces[i] != NULL && active_interfaces[i] == driver) {
            uint8_t* eth_data = (uint8_t*) buffer;
            ESP_LOGI("netif-tx", "Going to transmit a data packet: to "MACSTR" from "MACSTR" type=%02x%02x", MAC2STR(&eth_data[0]), MAC2STR(&eth_data[6]), eth_data[12], eth_data[13]);
            c_transmit_data_frame(active_interfaces[i]->interface_type, buffer, len);
            return ESP_OK;
        }
    }
    ESP_LOGE(TAG, "netif_tx: failed to find vif for handle %p", h);

    return ESP_FAIL;
}

static esp_err_t openmac_netif_transmit_wrap(void *h, void *buffer, size_t len, void *netstack_buf)
{
    return openmac_netif_transmit(h, buffer, len);
}


void openmac_netif_up(rs_mac_interface_type_t interface) {
    for (int i = 0; i < NUM_VIRTUAL_INTERFACES; i++) {
        if (active_interfaces[i] != NULL && active_interfaces[i]->interface_type == interface) {
            esp_netif_action_connected(active_interfaces[i]->base.netif, NULL, 0, NULL);
            return;
        }
    }
    ESP_LOGE(TAG, "trying to up vif %d but not active", interface);
}

void openmac_netif_down(rs_mac_interface_type_t interface) {
    for (int i = 0; i < NUM_VIRTUAL_INTERFACES; i++) {
        if (active_interfaces[i] != NULL && active_interfaces[i]->interface_type == interface) {
            esp_netif_action_disconnected(active_interfaces[i]->base.netif, NULL, 0, NULL);
            return;
        }
    }
    ESP_LOGE(TAG, "trying to down vif %d but not active", interface);
}

// Put Ethernet-formatted frame in MAC stack; does not take ownership of the buffer: after the function returns, you can delete/reuse it.
void openmac_netif_receive(rs_mac_interface_type_t interface, void* buffer, size_t len) {
    assert(buffer != NULL);

    for (int i = 0; i < NUM_VIRTUAL_INTERFACES; i++) {
        if (active_interfaces[i] != NULL && active_interfaces[i]->interface_type == interface) {
            esp_netif_receive(active_interfaces[i]->base.netif, buffer, len, buffer);
            return;
        }
    }
    // If we get here, the MAC stack passed us a frame that does not have a currently active interface
    ESP_LOGE(TAG, "received frame for vif %d but not active", interface);
}

// Free RX buffer
static void openmac_free(void *h, void* buffer)
{
    c_recycle_mac_rx_frame(buffer);
}

static esp_err_t openmac_driver_start(esp_netif_t * esp_netif, void * args)
{
    openmac_netif_driver_t* driver = args;
    driver->base.netif = esp_netif;
    esp_netif_driver_ifconfig_t driver_ifconfig = {
            .handle =  driver,
            .transmit = openmac_netif_transmit,
            .transmit_wrap = openmac_netif_transmit_wrap,
            .driver_free_rx_buffer = openmac_free
    };

    return esp_netif_set_driver_config(esp_netif, &driver_ifconfig);
}


openmac_netif_driver_t* openmac_create_if_driver()
{
    openmac_netif_driver_t* driver = calloc(1, sizeof(struct openmac_netif_driver));
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

    esp_netif_t* netif_openmac_sta = esp_netif_new(&cfg_sta);
    assert(netif_openmac_sta);

    openmac_netif_driver_t* driver = openmac_create_if_driver();
    if (driver == NULL) {
        ESP_LOGE(TAG, "Failed to create wifi interface handle");
        return ESP_FAIL;
    }

    driver->interface_type = STA_1_MAC_INTERFACE_TYPE;
    active_interfaces[0] = driver;

    esp_netif_attach(netif_openmac_sta, driver);
    esp_netif_set_hostname(netif_openmac_sta, "esp32-open-mac");
    esp_netif_set_mac(netif_openmac_sta, module_mac_addr);
    esp_netif_action_start(netif_openmac_sta, NULL, 0, NULL);
    return ESP_OK;
}