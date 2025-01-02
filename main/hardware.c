#include "freertos/FreeRTOS.h"

#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "soc/soc.h"
#include "soc/periph_defs.h"
#include "esp32/rom/ets_sys.h"

#include "string.h"

#include "proprietary.h" // contains all symbols from the binary blobs we still need
#include "hardware.h"
#include "hwinit.h"

#include "80211_mac_interface.h"

#define RX_BUFFER_AMOUNT 10

static const char* TAG = "hardware.c";
uint8_t iface_1_mac_addr[6] = {0x00, 0x23, 0x45, 0x67, 0x89, 0xab};
uint8_t iface_2_mac_addr[6] = {0x00, 0x20, 0x91, 0x00, 0x00, 0x00};
uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

inline void write_register(uint32_t address, uint32_t value) {
	*((volatile uint32_t*) address) = value;
}

inline uint32_t read_register(uint32_t address) {
	return *((volatile uint32_t*) address);
}

// there are 5 TX slots
// format: _BASE addresses are the base addresses
//         _OS amounts is the amount of 4-byte words in the offset between slots
// So for example, if the MAC_TX_PLCP0 for slot 0 is at 0x3ff73d20
// then the MAC_TX_PLCP0 for slot 1 will be at 0x3ff73d20 - 2 * 4 = 0x3ff73d18

#define MAC_TX_PLCP0_BASE _MMIO_ADDR(0x3ff73d20)
#define MAC_TX_PLCP0_OS (-2)

#define WIFI_TX_CONFIG_BASE _MMIO_ADDR(0x3ff73d1c)
#define WIFI_TX_CONFIG_OS (-2)


#define MAC_TX_PLCP1_BASE _MMIO_ADDR(0x3ff74258)
#define MAC_TX_PLCP1_OS (-0xf)

#define MAC_TX_PLCP2_BASE _MMIO_ADDR(0x3ff7425c)
#define MAC_TX_PLCP2_OS (-0xf)

#define MAC_TX_DURATION_BASE _MMIO_ADDR(0x3ff74268)
#define MAC_TX_DURATION_OS (-0xf)

#define MAC_TX_HT_SIG_BASE _MMIO_ADDR(0x3ff74260)
#define MAC_TX_HT_SIG_OS (-0xf)

#define MAC_TX_HT_UNKNOWN_BASE _MMIO_ADDR(0x3ff74264)
#define MAC_TX_HT_UNKNOWN_OS (-0xf)

#define WIFI_DMA_INT_STATUS _MMIO_DWORD(0x3ff73c48)
#define WIFI_DMA_INT_CLR _MMIO_DWORD(0x3ff73c4c)

#define WIFI_MAC_BITMASK_084 _MMIO_DWORD(0x3ff73084)
#define WIFI_NEXT_RX_DSCR _MMIO_DWORD(0x3ff7308c)
#define WIFI_LAST_RX_DSCR _MMIO_DWORD(0x3ff73090)
#define WIFI_BASE_RX_DSCR _MMIO_DWORD(0x3ff73088)

#define WIFI_TXQ_GET_STATE_COMPLETE _MMIO_DWORD(0x3ff73cc8)
#define WIFI_TXQ_CLR_STATE_COMPLETE _MMIO_DWORD(0x3ff73cc4)

// Collision or timeout
#define WIFI_TXQ_GET_STATE_ERROR _MMIO_DWORD(0x3ff73ccc0)
#define WIFI_TXQ_CLR_STATE_ERROR _MMIO_DWORD(0x3ff73ccbc)


#define WIFI_MAC_ADDR_SLOT_0 0x3ff73040
#define WIFI_MAC_ADDR_ACK_ENABLE_SLOT_0 0x3ff73064

#define WIFI_BSSID_FILTER_ADDR_SLOT_0 _MMIO_ADDR(0x3ff73000)


#define MAC_CTRL_REG _MMIO_DWORD(0x3ff73cb8)

typedef enum {
	RX_ENTRY,
	TX_ENTRY,
	CHANGE_CHANNEL_ENTRY,
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
	uint8_t channel;
} change_channel_queue_entry_t;

typedef struct {
	hardware_queue_entry_type_t type;
	union {
		rx_queue_entry_t rx;
		tx_queue_entry_t tx;
		change_channel_queue_entry_t change_channel;
	} content;
} hardware_queue_entry_t;

SemaphoreHandle_t tx_queue_resources = NULL;
SemaphoreHandle_t rx_queue_resources = NULL;

QueueHandle_t hardware_event_queue = NULL;

dma_list_item* rx_chain_begin = NULL;
dma_list_item* rx_chain_last = NULL;

volatile int interrupt_count = 0;

#define TX_SLOT_CNT 5

typedef struct {
	// dma_list_item must be 4-byte aligned (it's passed to hardware that only takes those addresses)
	struct {} __attribute__ ((aligned (4)));
	dma_list_item dma;
	
	rs_smart_frame_t* frame;
	bool in_use;
} tx_hardware_slot_t;

tx_hardware_slot_t tx_slots[TX_SLOT_CNT] = {};

uint32_t seqnum = 0;

void log_dma_item(dma_list_item* item) {
	ESP_LOGD("dma_item", "cur=%p owner=%d has_data=%d length=%d size=%d packet=%p next=%p", item, item->owner, item->has_data, item->length, item->size, item->packet, item->next);
}

void request_channel_change(uint8_t channel) {
	hardware_queue_entry_t msg = {.type = CHANGE_CHANNEL_ENTRY, .content.change_channel.channel = channel};
	if (xQueueSendToBack(hardware_event_queue, &msg, 0) != pdTRUE) {
		ESP_LOGE(TAG, "queueing channel change request failed");
		abort();
	}
}


bool transmit_80211_frame(rs_smart_frame_t* frame) {
	uint32_t slot = 0;

	// Find the first free TX slot
	for (slot = 0; slot < TX_SLOT_CNT; slot++) {
		if (!tx_slots[slot].in_use) {
			break;
		}
	}
	if (slot == TX_SLOT_CNT) {
		ESP_LOGE(TAG, "all tx slots full");
		return false;
	}
	ESP_LOGI(TAG, "using tx slot %d", (int) slot);

	dma_list_item* tx_item = &(tx_slots[slot].dma);
	// dma_list_item must be 4-byte aligned (it's passed to hardware that only takes those addresses)
	assert(((uint32_t)(tx_item) & 0b11) == 0);

	// TODO maybe take a mutex over the TX slots here?
	tx_slots[slot].in_use = true;
	tx_slots[slot].frame = frame;

	uint32_t size_len = frame->payload_length + 32;

	// Set & update sequence number
	// TODO remove this code
	frame->payload[22] = (seqnum & 0x0f) << 4;
	frame->payload[23] = (seqnum & 0xff0) >> 4;
	seqnum++;
	if (seqnum > 0xfff) seqnum = 0;

	ESP_LOGI(TAG, "len=%d",(int) frame->payload_length);
	ESP_LOG_BUFFER_HEXDUMP("to-transmit", frame->payload, frame->payload_length, ESP_LOG_INFO);

	tx_item->owner = 1;
	tx_item->has_data = 1;
	tx_item->length = frame->payload_length;
	tx_item->size = size_len;
	tx_item->packet = frame->payload;
	tx_item->next = NULL;

	WIFI_TX_CONFIG_BASE[WIFI_TX_CONFIG_OS*slot] = WIFI_TX_CONFIG_BASE[WIFI_TX_CONFIG_OS * slot] | 0xa;

	MAC_TX_PLCP0_BASE[MAC_TX_PLCP0_OS*slot] = (((uint32_t)(tx_item)) & 0xfffff) | (0x00600000);
	uint32_t rate = frame->rate;  // see wifi_phy_rate_t
	uint32_t is_ht = (rate >= 0x10);
	uint32_t is_short_gi = (rate >= 0x18);
	uint32_t crypto_key_slot = 0;

	MAC_TX_PLCP1_BASE[MAC_TX_PLCP1_OS*slot] = 0x10000000 | (frame->payload_length & 0xfff) | ((rate & 0x1f) << 12) | ((is_ht & 0b1) << 25) | ((crypto_key_slot & 0b11111) << 17);
	MAC_TX_PLCP2_BASE[MAC_TX_PLCP2_OS*slot] = 0x00000020;
	MAC_TX_DURATION_BASE[MAC_TX_DURATION_OS*slot] = 0;

	// check if this is a 802.11n HT frame
	// See also https://openofdm.readthedocs.io/en/latest/sig.html
	if (is_ht) {
		uint32_t ht_sig = 0;
		ht_sig |= rate & 0b111; // MCS
		ht_sig |= 0b0 << 7; // 20/40 MHz
		ht_sig |=  (frame->payload_length & 0xffff) << 8; // HT Length
		ht_sig |= 1 << 24; // smoothing recommended
		ht_sig |= 1 << 25; // not sounding
		ht_sig |= 1 << 26; // reserved
		ht_sig |= 0b0 << 27; // AMPDU
		ht_sig |= 0b00 << 28; // spatial stream idx
		ht_sig |= 0b0 << 30; // LDCP
		ht_sig |= is_short_gi << 31; // short GI
		MAC_TX_HT_SIG_BASE[MAC_TX_HT_SIG_OS*slot] = ht_sig;
		MAC_TX_HT_UNKNOWN_BASE[MAC_TX_HT_UNKNOWN_OS*slot] = (frame->payload_length & 0xffff) | 0x50000;
	}

	WIFI_TX_CONFIG_BASE[WIFI_TX_CONFIG_OS*slot] |= 0x02000000;
	WIFI_TX_CONFIG_BASE[WIFI_TX_CONFIG_OS*slot] |= 0x00003000;
	
	// Transmit: setting the 0xc0000000 bit in MAC_TX_PLCP0 enables transmission
	MAC_TX_PLCP0_BASE[MAC_TX_PLCP0_OS*slot] |= 0xc0000000;
	return true;
}

static void deinit_mac() {
	MAC_CTRL_REG = MAC_CTRL_REG | 0x17ff;
	while ((MAC_CTRL_REG & 0x2000) != 0) {
		// nothing
	}
}

static void init_mac() {
	MAC_CTRL_REG = MAC_CTRL_REG & 0xffffe800;
}

static void change_channel_to(uint8_t channel) {
	ESP_LOGE(TAG, "changing channel to %d", channel);
	if (channel <= 0 || channel >= 13) {
		ESP_LOGE(TAG, "channel %d not valid", channel);
		abort();
	}
	// but not actually
	deinit_mac();
	chip_v7_set_chan_nomac(channel, 0);
	disable_wifi_agc();
	init_mac();
	enable_wifi_agc();
}

// TODO if we try to TX packets before taking over, we don't get the interrupt and
//      forever consider that slot as occupied; so we need to:
// - make sure we only start transmitting after everything is initialized
// - find a way to recover from not getting an interrupt
static void processTxComplete() {
	uint32_t txq_state_complete = WIFI_TXQ_GET_STATE_COMPLETE;
	ESP_LOGW(TAG, "tx complete = %lx", txq_state_complete);
	if (txq_state_complete == 0) {
		return;
	}
	uint32_t slot = 31 - __builtin_clz(txq_state_complete);
	ESP_LOGW(TAG, "slot %lx is now free again", slot);
	uint32_t clear_mask = 1 << slot;
	WIFI_TXQ_CLR_STATE_COMPLETE |= clear_mask;
	// Periodic power calibration
	static uint8_t ctr = 0;
	ctr++;
	if (ctr % 4 == 0) {
		tx_pwctrl_background(1, 0);
	}
	// Recycle the buffer the packet was received in
	if (slot < TX_SLOT_CNT) {
		// TODO maybe take a mutex over the TX slots here?
		c_recycle_tx_smart_frame(tx_slots[slot].frame);
		tx_slots[slot].in_use = false;
		tx_slots[slot].frame = NULL;
	}
}

void IRAM_ATTR wifi_interrupt_handler(void* args) {
	interrupt_count++;
	uint32_t cause = WIFI_DMA_INT_STATUS;
	if (cause == 0) {
		return;
	}
	WIFI_DMA_INT_CLR = cause;

	if (cause & 0x800) {
		// TODO handle this with open-source code
		// wdev_process_panic_watchdog() is the closed-source way to recover from this
	}
	if (xSemaphoreTakeFromISR(rx_queue_resources, NULL)) {
		hardware_queue_entry_t queue_entry;
		queue_entry.type = RX_ENTRY;
		queue_entry.content.rx.interrupt_received = cause;
		// ESP_DRAM_LOGE("isr", "%08x", cause);
		bool higher_prio_task_woken = false;
		xQueueSendFromISR(hardware_event_queue, &queue_entry, &higher_prio_task_woken);
		if (higher_prio_task_woken) {
			portYIELD_FROM_ISR();
		}
	}
}

void setup_interrupt() {
	// See the documentation of intr_matrix_set in esp-idf/components/esp_rom/include/esp32s3/rom/ets_sys.h
	intr_matrix_set(0, ETS_WIFI_MAC_INTR_SOURCE, ETS_WMAC_INUM);

	// Replace the existing wDev_ProcessFiq interrupt
	xt_set_interrupt_handler(ETS_WMAC_INUM, wifi_interrupt_handler, NULL);
	xt_ints_on(1 << ETS_WMAC_INUM);
}

void print_rx_chain(dma_list_item* item) {
	// Debug print to display RX linked list
	int index = 0;
	ESP_LOGD("rx-chain", "base=%p next=%p last=%p", (dma_list_item*) WIFI_BASE_RX_DSCR, (dma_list_item*) WIFI_NEXT_RX_DSCR, (dma_list_item*) WIFI_LAST_RX_DSCR);
	while (item) {
		ESP_LOGD("rx-chain", "idx=%d cur=%p owner=%d has_data=%d length=%d size=%d packet=%p next=%p", index, item, item->owner, item->has_data, item->length, item->size, item->packet, item->next);
		item = item->next;
		index++;
	}
	ESP_LOGD("rx-chain", "base=%p next=%p last=%p", (dma_list_item*) WIFI_BASE_RX_DSCR, (dma_list_item*) WIFI_NEXT_RX_DSCR, (dma_list_item*) WIFI_LAST_RX_DSCR);
}

void set_rx_base_address(dma_list_item* item) {
	WIFI_BASE_RX_DSCR = (uint32_t) item;
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
	WIFI_MAC_BITMASK_084 |= 0x1;
	// Wait for confirmation from hardware
	while (WIFI_MAC_BITMASK_084 & 0x1);
}

void rs_recycle_dma_item(dma_list_item* item) {
	item->length = item->size;
	item->has_data = 0;
	if (rx_chain_begin) {
		rx_chain_last->next = item;
		update_rx_chain();
		if (WIFI_NEXT_RX_DSCR == 0x3ff00000) {
			dma_list_item* last_dscr = (dma_list_item*) WIFI_LAST_RX_DSCR;
			if (item == last_dscr) {
				rx_chain_last = item;
			} else {
				assert(last_dscr->next != 0);
				set_rx_base_address(last_dscr->next);
				rx_chain_last = item;
			}
		} else {
			rx_chain_last = item;
		}
	} else {
		rx_chain_begin = item;
		set_rx_base_address(item);
		rx_chain_last = item;
	}
}

void handle_rx_messages() {
	// print_rx_chain(rx_chain_begin);
	dma_list_item* current = rx_chain_begin;
	
	// This is a workaround for when we receive a lot of packets; otherwise we get stuck in this function,
	// handling packets for all eternity
	// This is much less of a problem now that we implement hardware filtering
	int received = 0;
	while (current && current->has_data) {
		dma_list_item* next = current->next;
		//TODO enable interrupt?

		received++;

		// update rx chain
		rx_chain_begin = next;
		current->next = NULL;
		c_hand_rx_to_mac_stack(current);
		
		//TODO disable interrupt?
		current = next;
		if (received > 10) {
			goto out;
		}
	}
	out:
	// TODO enable interrupt
}

static void set_enable_mac_addr_filter(uint8_t slot, bool enable) {
	// This will allow packets that match the filter to be queued in our reception queue
	// will also ack them once they arrive
	assert(slot <= 1);
	uint32_t addr = WIFI_MAC_ADDR_ACK_ENABLE_SLOT_0 + 8*slot;
	if (enable) {
		write_register(addr, read_register(addr) | 0x10000);
	} else {
		write_register(addr, read_register(addr) & ~(0x10000));
	}
}

static void set_mac_addr_filter(uint8_t slot, const uint8_t* addr) {
	assert(slot <= 1);
	write_register(WIFI_MAC_ADDR_SLOT_0 + slot*8, addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24);
	write_register(WIFI_MAC_ADDR_SLOT_0 + slot*8 + 4, addr[4] | addr[5] << 8);
	write_register(WIFI_MAC_ADDR_SLOT_0 + slot*8 + 8*4, ~0); // mask bits
	write_register(WIFI_MAC_ADDR_ACK_ENABLE_SLOT_0 + slot*8, read_register(WIFI_MAC_ADDR_ACK_ENABLE_SLOT_0 + slot*8) | 0xffff); // mask bits
}

static void set_enable_bssid_filter(uint8_t slot, bool enable) {
	assert(slot <= 1);
	if (enable) {
		*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2 + 9) |= 0x10000;
	} else {
		*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2 + 9) &= ~(0x10000);
	}
}

// also used in rust stack
void set_bssid_filter(uint8_t slot, const uint8_t* addr) {
	assert(slot <= 1);
	// disable
	*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2 + 9) &= 0xfffeffff;

	*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2) = addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24;
	*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2 + 1) = addr[4] | addr[5] << 8;
	*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2 + 8) = ~0; // mask bits
	*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2 + 9) = 0xffff; // mask bits

	// enable
	*(WIFI_BSSID_FILTER_ADDR_SLOT_0 + slot*2 + 9) |= 0x10000;
}

// related to beacons/probe requests?
void set_some_kind_of_rx_policy(uint8_t slot, bool enable) {
	assert(slot <= 1);
	if (enable) {
		*(volatile uint32_t*)(0x3ff730d8 + 4*slot) |= 0x110;
	} else {
		*(volatile uint32_t*)(0x3ff730d8 + 4*slot) &= ~0x110;
	}
}

void filters_set_scanning_mode(uint8_t interface, const uint8_t* own_mac) {
	set_mac_addr_filter(interface, own_mac);
	set_bssid_filter(interface, own_mac);

	set_enable_mac_addr_filter(interface, true);
	set_enable_bssid_filter(interface, true);
	set_some_kind_of_rx_policy(interface, true);
}

void filters_set_client_mode(uint8_t interface, const uint8_t* own_mac, const uint8_t* bssid) {
	set_mac_addr_filter(interface, own_mac);
	set_bssid_filter(interface, bssid);

	set_enable_mac_addr_filter(interface, true);
	set_enable_bssid_filter(interface, true);
	set_some_kind_of_rx_policy(interface, false);
}

void hal_mac_tsf_reset(uint8_t a);

void filters_set_ap_mode(uint8_t interface, const uint8_t* bssid) {
	set_mac_addr_filter(interface, bssid);
	set_bssid_filter(interface, bssid);

	set_enable_mac_addr_filter(interface, true);
	set_enable_bssid_filter(interface, true);
	set_some_kind_of_rx_policy(interface, false);

	hal_mac_tsf_reset(1);
	WIFI_MAC_BITMASK_084 |= 0x80000000;
}

void wifi_hardware_task(void* pvArguments) {
	hardware_event_queue = xQueueCreate(RX_BUFFER_AMOUNT+10, sizeof(hardware_queue_entry_t));
	assert(hardware_event_queue);
	rx_queue_resources = xSemaphoreCreateCounting(RX_BUFFER_AMOUNT, RX_BUFFER_AMOUNT);
	assert(rx_queue_resources);
	tx_queue_resources = xSemaphoreCreateCounting(10, 10);
	assert(tx_queue_resources);

	hwinit();

	setup_interrupt();

	setup_rx_chain();

	ESP_LOGW(TAG, "Starting to receive messages");

	set_enable_mac_addr_filter(0, false);
	set_enable_bssid_filter(0, false);

	set_enable_mac_addr_filter(1, false);
	set_enable_bssid_filter(1, false);

	set_some_kind_of_rx_policy(0, false);
	set_some_kind_of_rx_policy(1, false);

	// acking will only happen if the hardware puts the packet in an RX buffer

	// We're ready now, start the MAC task
	xTaskCreatePinnedToCore(&c_mac_task, "rs_wifi", 4096, NULL, 22, NULL, 0);
	vTaskDelay(50 / portTICK_PERIOD_MS);
	
	
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
					ESP_LOGW(TAG, "HW RX");
					handle_rx_messages();
				}
				if (cause & 0x80) {
					processTxComplete();
				}
				if (cause & 0x80000) {
					ESP_LOGE(TAG, "lmacProcessAllTxTimeout");
				}
				if (cause & 0x100) {
					ESP_LOGE(TAG, "lmacProcessCollisions");
				}
				xSemaphoreGive(rx_queue_resources);
			} else if (queue_entry.type == TX_ENTRY) {
				ESP_LOGI(TAG, "TX from queue");
				// TODO: implement retry
				xSemaphoreGive(tx_queue_resources);
			} else if (queue_entry.type == CHANGE_CHANNEL_ENTRY) {
				uint8_t desired_channel = queue_entry.content.change_channel.channel;
				change_channel_to(desired_channel);
			} else {
				ESP_LOGI(TAG, "unknown queue type");
			}
		}
		// ESP_LOGW(TAG, "interrupt count=%d", interrupt_count);
	}
}
