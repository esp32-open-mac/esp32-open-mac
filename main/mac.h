#include "hardware.h"

void open_mac_rx_callback(wifi_promiscuous_pkt_t* packet);

void mac_task(void* pvParameters);

esp_err_t openmac_netif_start();
void openmac_netif_up();
void openmac_netif_down();
