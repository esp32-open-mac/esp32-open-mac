#include <stdint.h>
#include <stdbool.h>
#include <stddef.h> 

typedef enum {
    EVENT_TYPE_MAC_TX_DATA_FRAME,
    EVENT_TYPE_MAC_FREE_RX_DATA,
    EVENT_TYPE_PHY_RX_DATA,
} rs_event_type_t;

typedef struct {
    uint8_t* payload;
    size_t payload_length;
    uint32_t rate;
} rs_smart_frame_t; // has a frame, and the metadata (rate, length, ...)

/*Called from the Rust MAC stack, gets the next event*/
bool rs_get_next_mac_event_raw(uint32_t ms_to_wait, rs_event_type_t* event_type, void** ptr);

/*Called from the Rust MAC stack, to obtain a smart frame, which can then be filled in*/
rs_smart_frame_t* rs_get_smart_frame(size_t size_hint);

/*Called from the Rust MAC stack, to TX a smart frame previously obtained via rs_get_smart_frame*/
void rs_tx_smart_frame(rs_smart_frame_t* frame);

/*Called from the Rust MAC stack, to pass a data frame to the MAC stack. Expects the frame to be in Ethernet format*/
void rs_rx_mac_frame(uint8_t* frame, size_t len);
