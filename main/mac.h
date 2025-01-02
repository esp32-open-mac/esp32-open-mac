#include "hardware.h"

void mac_task(void* pvParameters);

esp_err_t openmac_netif_start();
void openmac_netif_up();
void openmac_netif_down();
