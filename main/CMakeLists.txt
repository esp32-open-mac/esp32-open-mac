idf_component_register(SRCS "hardware.c" "main.c" "mac.c" "hwinit.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_netif esp_phy esp_timer 80211_mac_rust
                    PRIV_REQUIRES driver esptool_py esp_pm esp_timer nvs_flash hal lwip)
