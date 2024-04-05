#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_phy_init.h"

static const char* TAG = "hwinit";

void wifi_start_process();

void hwinit() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	cfg.static_rx_buf_num = 2; // we won't use these buffers, so reduce the amount from default 10, so we don't waste as much memory
	// Disable AMPDU and AMSDU for now, we don't support this (yet)
	cfg.ampdu_rx_enable = false;
	cfg.ampdu_tx_enable = false;
	cfg.amsdu_tx_enable = false;
	cfg.nvs_enable = false;
    ESP_LOGW(TAG, "calling esp_wifi_init");
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	// esp_phy_common_clock_enable();
	ESP_LOGW(TAG, "done esp_wifi_init");

	ESP_LOGW(TAG, "Starting wifi_hardware task, running on %d", xPortGetCoreID());
	ESP_LOGW(TAG, "calling esp_wifi_set_mode");
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_LOGW(TAG, "done esp_wifi_set_mode");

	ESP_LOGW(TAG, "calling esp_wifi_start");
	wifi_start_process();
	ESP_LOGW(TAG, "done esp_wifi_start");
}