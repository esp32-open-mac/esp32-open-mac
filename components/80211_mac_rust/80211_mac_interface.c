#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "80211_mac_interface.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#define IEEE80211_MAX_FRAME_LEN   (2352)

// TODO check this is correct
#define IEEE80211_MAX_PAYLOAD_LEN (2304)

#define NUM_TX_SMART_FRAME_BUFFERS (5)
#define NUM_RX_BUFFERS (5)

typedef struct {
	void* ptr;
	rs_event_type_t event_type;
	size_t len;
} rust_mac_event_queue_item_t;

typedef struct {
	rs_smart_frame_t* frame;
	bool in_use;
} smart_frame_tracker_t;

typedef struct {
	uint8_t* buffer;
	bool in_use;
	size_t buffersize;
} mac_rx_frame_t;

static QueueHandle_t rust_mac_event_queue = NULL;
smart_frame_tracker_t smart_frame_tracker_list[NUM_TX_SMART_FRAME_BUFFERS] = {{0}};
mac_rx_frame_t mac_rx_frame_list[NUM_RX_BUFFERS] = {{0}};
bool init_done = false;

void interface_init() {
	// TODO remove hard-coded 30
	rust_mac_event_queue = xQueueCreate(30 + NUM_TX_SMART_FRAME_BUFFERS, sizeof(rust_mac_event_queue_item_t));
	assert(rust_mac_event_queue);

	for (int i = 0; i < NUM_TX_SMART_FRAME_BUFFERS; i++) {
		uint8_t* payload = malloc(IEEE80211_MAX_FRAME_LEN);
		rs_smart_frame_t* smart_frame = malloc(sizeof(rs_smart_frame_t));
		smart_frame->payload = payload;
		smart_frame->payload_size = IEEE80211_MAX_FRAME_LEN;
		smart_frame_tracker_list[i].frame = smart_frame;
		smart_frame_tracker_list[i].in_use = false;
	}
	for (int i = 0; i < NUM_RX_BUFFERS; i++) {
		// TODO also allocate smaller buffers?
		uint8_t* buffer = malloc(IEEE80211_MAX_PAYLOAD_LEN);
		mac_rx_frame_t rx_frame = {.buffer = buffer, .buffersize = IEEE80211_MAX_PAYLOAD_LEN, .in_use = false};
		mac_rx_frame_list[i] = rx_frame;
	}
	init_done = true;
}

bool rs_get_next_mac_event_raw(uint32_t ms_to_wait, rs_event_type_t* event_type, void** ptr,  size_t* len) {
	rust_mac_event_queue_item_t item;
	if (xQueueReceive(rust_mac_event_queue, &item, ms_to_wait / portTICK_PERIOD_MS)) {
		*event_type = item.event_type;
		*ptr = item.ptr;
		*len = item.len;
		return true;
	}
	return false;
}

int64_t esp_timer_get_time();

int64_t rs_get_time_us() {
	return esp_timer_get_time();
}

// declaration from IP
// RX'ed 802.11 packets -> RX queue of MAC stack
void openmac_netif_receive(rs_mac_interface_type_t interface, void* buffer, size_t len);

/*Called from the Rust MAC stack, to obtain a frame to receive MAC data in and pass it to ESP-NETIF */
uint8_t* rs_get_mac_rx_frame(size_t size_required) {
	for (int i = 0; i < NUM_RX_BUFFERS; i++) {
		if (!mac_rx_frame_list[i].in_use && mac_rx_frame_list[i].buffersize >= size_required) {
			mac_rx_frame_list[i].in_use = true;
			printf("handing out %d %p\n", i, mac_rx_frame_list[i].buffer);
			return mac_rx_frame_list[i].buffer;
		}
	}
	return NULL;
}

/*Called from the Rust MAC stack, to pass a previously obtained data frame buffer to ESP-NETIF. Expects the frame to be in Ethernet format. Does not take ownership of the data*/
void rs_rx_mac_frame(rs_mac_interface_type_t interface, uint8_t* frame, size_t len) {
	openmac_netif_receive(interface, frame, len);
}

/*
  Called from the ESP-NETIF stack to recycle a MAC RX frame after it was sent. Takes ownership of the buffer.
*/
void c_recycle_mac_rx_frame(uint8_t* buffer) {
	printf("recycling %p\n", buffer);
	for (int i = 0; i < NUM_RX_BUFFERS; i++) {
		if (mac_rx_frame_list[i].buffer == buffer) {
			mac_rx_frame_list[i].in_use = false;
			return;
		}
	}
	// if we reached this, we somehow recycled a frame that wasn't in the list
	abort();
}

/*Called from the Rust MAC stack, to obtain a smart frame from the hardware, which can then be filled in*/
rs_smart_frame_t* rs_get_smart_frame(size_t size_required) {
	for (int i = 0; i < NUM_TX_SMART_FRAME_BUFFERS; i++) {
		if (!smart_frame_tracker_list[i].in_use && smart_frame_tracker_list[i].frame->payload_size >= size_required) {
			smart_frame_tracker_list[i].in_use = true;
			smart_frame_tracker_list[i].frame->payload_length = 0;
			return smart_frame_tracker_list[i].frame;
		}
	}
	return NULL;
}

// declaration from hardware:
bool transmit_80211_frame(rs_smart_frame_t* frame);


/*
  Called from the hardware stack to recycle a smart frame after it was sent
*/
void c_recycle_tx_smart_frame(rs_smart_frame_t* frame) {
	for (int i = 0; i < NUM_TX_SMART_FRAME_BUFFERS; i++) {
		if (smart_frame_tracker_list[i].frame == frame) {
			smart_frame_tracker_list[i].in_use = false;
			return;
		}
	}
	// if we reached this, we somehow recycled a frame that doesn't correspond to a smart frame
	abort();
}

/*Called from the Rust MAC stack, to TX a smart frame previously obtained via rs_get_smart_frame*/
void rs_tx_smart_frame(rs_smart_frame_t* frame) {
	// TODO eventually use a frame queue when we want to send more than 5 frames at a time
    if (!transmit_80211_frame(frame)) {
		// failed to send
		// TODO mutex here?
		c_recycle_tx_smart_frame(frame);
	}
}

// Called from hardware to hand frames it received to the Rust MAC stack
void c_hand_rx_to_mac_stack(dma_list_item* item) {
	rust_mac_event_queue_item_t to_queue;
	to_queue.event_type = EVENT_TYPE_PHY_RX_DATA;
	to_queue.ptr = item;
	// TODO can this queue be full?
	if (xQueueSendToBack(rust_mac_event_queue, &to_queue, 0) != pdTRUE) {
		printf("failed to push HW RX to Rust\n");
		abort();
	} else {
		printf("handed to RX stack\n");
	}
}

void openmac_netif_up(rs_mac_interface_type_t interface);
void openmac_netif_down(rs_mac_interface_type_t interface);

void rs_mark_iface_up(rs_mac_interface_type_t interface) {
	openmac_netif_up(interface);
}

void rs_mark_iface_down(rs_mac_interface_type_t interface) {
	openmac_netif_down(interface);
}

void rs_recycle_mac_tx_data(uint8_t* data) {
	free(data);
}

void request_channel_change(uint8_t channel);

void rs_change_channel(uint8_t channel) {
	request_channel_change(channel);
}

void filters_set_scanning_mode(uint8_t interface, const uint8_t* own_mac);
void filters_set_client_mode(uint8_t interface, const uint8_t* own_mac, const uint8_t* bssid);
void filters_set_ap_mode(uint8_t interface, const uint8_t* bssid);

void rs_filters_set_scanning(uint8_t interface, const uint8_t* own_mac) {
	filters_set_scanning_mode(interface, own_mac);
}

void rs_filters_set_client_with_bssid(uint8_t interface, const uint8_t* own_mac, const uint8_t* bssid) {
	filters_set_client_mode(interface, own_mac, bssid);
}

void rs_filters_set_ap_mode(uint8_t interface, const uint8_t* addr) {
	filters_set_ap_mode(interface, addr);
}

// Called from the C ESP-NETIF stack to request the Rust MAC stack to TX a frame
// This function does NOT take ownership of the frame, so you're allowed to reuse the buffer directly after this returns
void c_transmit_data_frame(rs_mac_interface_type_t interface, uint8_t* frame, size_t len) {
	if (!rust_mac_event_queue) {
		printf("netif-tx, but no rust queue yet\n");
		return;
	}

	// TODO make sure we don't flood the stack by sending too much frames
	// maybe use a counting semaphore?
	uint8_t* queued_buffer = malloc(1 + len);
	queued_buffer[0] = interface;
	memcpy(queued_buffer + 1, frame, len);

	rust_mac_event_queue_item_t to_queue = {0};
	to_queue.event_type = EVENT_TYPE_MAC_TX_DATA_FRAME;
	to_queue.ptr = queued_buffer;
	to_queue.len = len + 1;
	if (xQueueSendToBack(rust_mac_event_queue, &to_queue, 0) != pdTRUE) {
		rs_recycle_mac_tx_data(queued_buffer);
	}
}


void c_mac_task() {
	interface_init();
	rust_mac_task();
}