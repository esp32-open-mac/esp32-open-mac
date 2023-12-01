#include "freertos/FreeRTOS.h"

#include "esp_system.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "soc/soc.h"
#include "soc/periph_defs.h"
#include "esp32/rom/ets_sys.h"

#include "nvs_flash.h"
#include "string.h"

#include "proprietary.h" // contains all symbols from the binary blobs we still need
#include "hardware.h"

#define RX_BUFFER_AMOUNT 10

static const char* TAG = "hardware.c";

inline void write_register(uint32_t address, uint32_t value) {
	*((volatile uint32_t*) address) = value;
}

inline uint32_t read_register(uint32_t address) {
	return *((volatile uint32_t*) address);
}

#define WIFI_DMA_OUTLINK 0x3ff73d20
#define WIFI_TX_CONFIG_0 0x3ff73d1c

#define MAC_TX_PLCP1 0x3ff74258
#define MAC_TX_PLCP2 0x3ff7425c
#define MAC_TX_DURATION 0x3ff74268

#define WIFI_DMA_INT_STATUS 0x3ff73c48
#define WIFI_DMA_INT_CLR 0x3ff73c4c

#define WIFI_MAC_BITMASK_084 0x3ff73084
#define WIFI_NEXT_RX_DSCR 0x3ff7308c
#define WIFI_LAST_RX_DSCR 0x3ff73090
#define WIFI_BASE_RX_DSCR 0x3ff73088

typedef struct __attribute__((packed)) dma_list_item {
	uint16_t size : 12;
	uint16_t length : 12;
	uint8_t _unknown : 6;
	uint8_t has_data : 1;
	uint8_t owner : 1; // What does this mean?
	void* packet;
	struct dma_list_item* next;
} dma_list_item;

typedef enum {
	RX_ENTRY,
	TX_ENTRY
} hardware_queue_entry_type_t;

typedef struct
{
	uint32_t interrupt_received;
} rx_queue_entry_t;

typedef struct
{
	uint8_t* packet;
	uint32_t len;
} tx_queue_entry_t;

typedef struct {
	hardware_queue_entry_type_t type;
	union {
		rx_queue_entry_t rx;
		tx_queue_entry_t tx;
	} content;
} hardware_queue_entry_t;

SemaphoreHandle_t tx_queue_resources = NULL;
SemaphoreHandle_t rx_queue_resources = NULL;

QueueHandle_t hardware_event_queue = NULL;

dma_list_item* rx_chain_begin = NULL;
dma_list_item* rx_chain_last = NULL;

volatile int interrupt_count = 0;

// TODO: have more than 1 TX slot
dma_list_item* tx_item = NULL;
uint8_t* tx_buffer = NULL;

uint64_t last_transmit_timestamp = 0;
uint32_t seqnum = 0;

void setup_tx_buffers() {
	tx_item = calloc(1, sizeof(dma_list_item));
	tx_buffer = calloc(1, 1600);
}

void log_dma_item(dma_list_item* item) {
	ESP_LOGD("dma_item", "cur=%p owner=%d has_data=%d length=%d size=%d packet=%p next=%p", item, item->owner, item->has_data, item->length, item->size, item->packet, item->next);
}

bool transmit_packet(uint8_t* packet, uint32_t buffer_len) {
	// 50 ms for safety, it's likely much shorter
	// TODO: figure out how we can know we can recycle the packet
	if (esp_timer_get_time() - last_transmit_timestamp < 50000) {
		ESP_LOGI(TAG, "Not transmitting packet, last transmit too recent");
		return false;
	}

	memcpy(tx_buffer, packet, buffer_len);
	uint32_t size_len = buffer_len + 32;

	// Update sequence number
	tx_buffer[22] = (seqnum & 0x0f) << 4;
	tx_buffer[23] = (seqnum & 0xff0) >> 4;
	seqnum++;
	if (seqnum > 0xfff) seqnum = 0;


	ESP_LOGI(TAG, "len=%d",(int) buffer_len);
	ESP_LOG_BUFFER_HEXDUMP("to-transmit", tx_buffer, buffer_len, ESP_LOG_INFO);

	tx_item->owner = 1;
	tx_item->has_data = 1;
	tx_item->length = buffer_len;
	tx_item->size = size_len;
	tx_item->packet = tx_buffer;
	tx_item->next = NULL;

	write_register(WIFI_TX_CONFIG_0, read_register(WIFI_TX_CONFIG_0) | 0xa);

	write_register(WIFI_DMA_OUTLINK,
		(((uint32_t)tx_item) & 0xfffff) |
		(0x00600000));

	write_register(MAC_TX_PLCP1, 0x10000000 | buffer_len);
	write_register(MAC_TX_PLCP2, 0x00000020);
	write_register(MAC_TX_DURATION, 0);
	
	write_register(WIFI_TX_CONFIG_0, read_register(WIFI_TX_CONFIG_0) | 0x02000000);

	write_register(WIFI_TX_CONFIG_0, read_register(WIFI_TX_CONFIG_0) | 0x00003000);
	
	// Transmit: setting the 0xc0000000 bit in WIFI_DMA_OUTLINK enables transmission
	write_register(WIFI_DMA_OUTLINK, read_register(WIFI_DMA_OUTLINK) | 0xc0000000);
	// TODO: instead of sleeping, figure out how to know that our packet was sent
	last_transmit_timestamp = esp_timer_get_time();
	return true;
}

void IRAM_ATTR wifi_interrupt_handler(void* args) {
	interrupt_count++;
	uint32_t cause = read_register(WIFI_DMA_INT_STATUS);
	if (cause == 0) {
		return;
	}
	write_register(WIFI_DMA_INT_CLR, cause);

	if (cause & 0x800) {
		// TODO handle this with open-source code
		// wdev_process_panic_watchdog() is the closed-source way to recover from this
	}
	volatile bool tmp = false;
	if (xSemaphoreTakeFromISR(rx_queue_resources, &tmp)) {
		hardware_queue_entry_t queue_entry;
		queue_entry.type = RX_ENTRY;
		queue_entry.content.rx.interrupt_received = cause;
		xQueueSendFromISR(hardware_event_queue, &queue_entry, NULL);
	}
}

void setup_interrupt() {
	// See the documentation of intr_matrix_set in esp-idf/components/esp_rom/include/esp32s3/rom/ets_sys.h
	intr_matrix_set(0, ETS_WIFI_MAC_INTR_SOURCE, ETS_WMAC_INUM);
	
	// Wait for interrupt to be set, so we can replace it
	while (_xt_interrupt_table[ETS_WMAC_INUM*portNUM_PROCESSORS+xPortGetCoreID()].handler == &xt_unhandled_interrupt) {
		vTaskDelay(100 / portTICK_PERIOD_MS);
		ESP_LOGW(TAG, "Waiting for interrupt to become set");
	}

	// Replace the existing wDev_ProcessFiq interrupt
	xt_set_interrupt_handler(ETS_WMAC_INUM, wifi_interrupt_handler, NULL);
	xt_ints_on(1 << ETS_WMAC_INUM);
}

void print_rx_chain(dma_list_item* item) {
	// Debug print to display RX linked list
	int index = 0;
	ESP_LOGD("rx-chain", "base=%p next=%p last=%p", (dma_list_item*) read_register(WIFI_BASE_RX_DSCR), (dma_list_item*) read_register(WIFI_NEXT_RX_DSCR), (dma_list_item*) read_register(WIFI_LAST_RX_DSCR));
	while (item) {
		ESP_LOGD("rx-chain", "idx=%d cur=%p owner=%d has_data=%d length=%d size=%d packet=%p next=%p", index, item, item->owner, item->has_data, item->length, item->size, item->packet, item->next);
		item = item->next;
		index++;
	}
	ESP_LOGD("rx-chain", "base=%p next=%p last=%p", (dma_list_item*) read_register(WIFI_BASE_RX_DSCR), (dma_list_item*) read_register(WIFI_NEXT_RX_DSCR), (dma_list_item*) read_register(WIFI_LAST_RX_DSCR));
}

void set_rx_base_address(dma_list_item* item) {
	write_register(WIFI_BASE_RX_DSCR, (uint32_t) item);
}

void setup_rx_chain() {
	// This function sets up the linked list needed for the Wi-Fi MAC RX functionality
	dma_list_item* prev = NULL;
	for (int i = 0; i < RX_BUFFER_AMOUNT; i++) {
		dma_list_item* item = malloc(sizeof(dma_list_item));
		item->has_data = 0;
		item->owner = 1;
		item->size = 1600;
		item->length = item->size;

		uint8_t* packet = malloc(1600); // TODO verify that this does not need to be bigger
		item->packet = packet;
		item->next = prev;
		prev = item;
		if (!rx_chain_last) {
			rx_chain_last = item;
		}
	}
	set_rx_base_address(prev);
	rx_chain_begin = prev;
}

void update_rx_chain() {
	write_register(WIFI_MAC_BITMASK_084, read_register(WIFI_MAC_BITMASK_084) | 0x1);
	// Wait for confirmation from hardware
	while (read_register(WIFI_MAC_BITMASK_084) & 0x1);
}

void handle_rx_messages(rx_callback rxcb) {
	dma_list_item* current = rx_chain_begin;
	// TODO disable interrupt
	while (current) {
		dma_list_item* next = current->next;
		if (current->has_data) {
			//TODO enable interrupt

			// Has data, but actual 802.11 MAC frame only starts at 28 bytes into the packet
			// The data before contains packet metadata
			wifi_promiscuous_pkt_t* packet = current->packet;
			// packet->rx_ctrl.sig_len includes the FCS (4 bytes), but we don't need this

			// call callback of upper layer
			rxcb(packet);
			// Recycle DMA item and buffer
			rx_chain_begin = current->next;
			current->next = NULL;
			current->length = current->size;
			current->has_data = 0;

			// This puts the DMA buffer back in the linked list
			// TODO: this code looks pretty ugly and might not be optimal
			if (rx_chain_begin) {
				rx_chain_last->next = current;
				update_rx_chain();
				if (read_register(WIFI_NEXT_RX_DSCR) == 0x3ff00000) {
					dma_list_item* last_dscr = (dma_list_item*) read_register(WIFI_LAST_RX_DSCR);
					if (current == last_dscr) {
						rx_chain_last = current;
					} else {
						set_rx_base_address(last_dscr->next);
						rx_chain_last = current;
					}
				} else {
					rx_chain_last = current;
				}
			} else {
				rx_chain_begin = current;
				set_rx_base_address(current);
				rx_chain_last = current;
			}
			//TODO disable interrupt
		}
		current = next;
	}
	// TODO enable interrupt
}

bool wifi_hardware_tx_func(uint8_t* packet, uint32_t len) {
	if (!xSemaphoreTake(tx_queue_resources, 1)) {
		ESP_LOGE(TAG, "TX semaphore full!");
		return false;
	}
	uint8_t* queue_copy = (uint8_t*) malloc(len);
	memcpy(queue_copy, packet, len);
	hardware_queue_entry_t queue_entry;
	queue_entry.type = TX_ENTRY;
	queue_entry.content.tx.len = len;
	queue_entry.content.tx.packet = queue_copy;
	xQueueSendToBack(hardware_event_queue, &queue_entry, 0);
	ESP_LOGI(TAG, "TX entry queued");
	return true;
}

void wifi_hardware_task(hardware_mac_args* pvParameter) {
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	cfg.static_rx_buf_num = 2; // we won't use these buffers, so reduce the amount from default 10, so we don't waste as much memory
	// Disable AMPDU and AMSDU for now, we don't support this (yet)
	cfg.ampdu_rx_enable = false;
	cfg.ampdu_tx_enable = false;
	cfg.amsdu_tx_enable = false;
	cfg.nvs_enable = false;

	// Print MAC addresses
	for (int i = 0; i < 2; i++) {
		uint8_t mac[6] = {0};
		if (esp_wifi_get_mac(i, mac) == ESP_OK) {
			ESP_LOGW(TAG, "MAC %d = %02x:%02x:%02x:%02x:%02x:%02x", i, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
	}

	hardware_event_queue = xQueueCreate(RX_BUFFER_AMOUNT+10, sizeof(hardware_queue_entry_t));
	assert(hardware_event_queue);
	rx_queue_resources = xSemaphoreCreateCounting(RX_BUFFER_AMOUNT, RX_BUFFER_AMOUNT);
	assert(rx_queue_resources);
	tx_queue_resources = xSemaphoreCreateCounting(10, 10);
	assert(tx_queue_resources);

	ESP_LOGW(TAG, "calling esp_wifi_init");
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_LOGW(TAG, "done esp_wifi_init");

	ESP_LOGW(TAG, "Starting open_mac_task, running on %d", xPortGetCoreID());
	ESP_LOGW(TAG, "calling esp_wifi_set_mode");
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_LOGW(TAG, "done esp_wifi_set_mode");

	ESP_LOGW(TAG, "calling esp_wifi_start");
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_LOGW(TAG, "done esp_wifi_start");

	ESP_LOGW(TAG, "calling esp_wifi_set_promiscuous");
	esp_wifi_set_promiscuous(true);
	ESP_LOGW(TAG, "done esp_wifi_set_promiscuous");

	setup_interrupt();

	// ppTask is a FreeRTOS task included in the esp32-wifi-lib blob
	// It reads from a queue that the proprietary WMAC interrupt handler writes to
	// We kill it to make sure that no proprietary code is running anymore
	ESP_LOGW(TAG, "Killing proprietary wifi task (ppTask)");
	pp_post(0xf, 0);

	// TODO: instead of promisc mode, set RX policy with (see wifi_set_rx_policy)
	// This will filter the 802.11 frames in hardware, based on their MAC address

	setup_rx_chain();
	setup_tx_buffers();

	pvParameter->_tx_func_callback(&wifi_hardware_tx_func);
	ESP_LOGW(TAG, "Starting to receive messages");
	
	while (true) {
		hardware_queue_entry_t queue_entry;
		if (xQueueReceive(hardware_event_queue, &(queue_entry), 10)) {
			if (queue_entry.type == RX_ENTRY) {
				uint32_t cause = queue_entry.content.rx.interrupt_received;
				// ESP_LOGW(TAG, "interrupt = 0x%08lx", cause);
				if (cause & 0x800) {
					// Watchdog panic
					// TODO process this
					// TODO what pets this watchdog?
					// ESP_LOGW(TAG, "watchdog panic, how do we pet it?");
				}
				if (cause & 0x600000) {
					// TODO this is bad, we should reboot
					ESP_LOGE(TAG, "something bad, we should reboot");
				}
				if (cause & 0x1000024) {
					// ESP_LOGW(TAG, "received message");
					handle_rx_messages(pvParameter->_rx_callback);
				}
				if (cause & 0x80) {
					// ESP_LOGW(TAG, "lmacPostTxComplete");
				}
				if (cause & 0x80000) {
					// ESP_LOGW(TAG, "lmacProcessAllTxTimeout");
				}
				if (cause & 0x100) {
					// ESP_LOGW(TAG, "lmacProcessCollisions");
				}
				xSemaphoreGive(rx_queue_resources);
			} else if (queue_entry.type == TX_ENTRY) {
				ESP_LOGI(TAG, "TX from queue");
				// TODO: implement retry
				// (we might not actually need it, but how do we know a packet has been transmitted and we can recycle its content)
				transmit_packet(queue_entry.content.tx.packet, queue_entry.content.tx.len);
				free(queue_entry.content.tx.packet);
				xSemaphoreGive(tx_queue_resources);
			} else {
				ESP_LOGI(TAG, "unknown queue type");
			}
		}
		// ESP_LOGW(TAG, "interrupt count=%d", interrupt_count);
	}
}
