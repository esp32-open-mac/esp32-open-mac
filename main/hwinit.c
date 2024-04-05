#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_phy_init.h"

static const char* TAG = "hwinit";

// Closed source symbols:
void wifi_hw_start(int a);
void wifi_module_enable();
void esp_phy_enable();
void wifi_reset_mac();
void ic_mac_init();
void chm_init(void* ptr);
void ic_enable();
void chip_enable();
void pm_noise_check_enable();
extern void* g_ic;
// End of closed source symbols

// Open source symbols:
esp_err_t adc2_wifi_acquire();
// End of open source symbols

void wifi_station_start_openmac() {
    // this does hal_enable_sta_tsf and ic_set_vif; which we already handle in open code
} 

esp_err_t _do_wifi_start_openmac(wifi_mode_t mode) {
    wifi_station_start_openmac();
    return ESP_OK;
}


void wifi_hw_start_openmac(wifi_mode_t mode) {
    // wifi_apb80m_request_wrapper is empty on ESP32
 
    // wifi_clock_enable_wrapper =
    wifi_module_enable();
    
    esp_phy_enable();

    // coex_enable_wrapper is empty on ESP32
    
    wifi_reset_mac();
    ic_mac_init();
    chm_init(&g_ic);
    ic_enable();
    chip_enable();
    pm_noise_check_enable();
}

void wifi_start_process_openmac() {
	ESP_ERROR_CHECK(adc2_wifi_acquire());
    wifi_hw_start_openmac(0);
    // not needed: ESP_ERROR_CHECK(wifi_mode_set(WIFI_MODE_STA));
    ESP_ERROR_CHECK(_do_wifi_start_openmac(WIFI_MODE_STA));
}

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
	wifi_start_process_openmac();
	ESP_LOGW(TAG, "done esp_wifi_start");
}