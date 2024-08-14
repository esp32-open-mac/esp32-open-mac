#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::c_void;
use core::marker::PhantomData;
use core::panic::PanicInfo;

use ieee80211::common::{CapabilitiesInformation, FCFFlags};
use ieee80211::elements::{DSSSParameterSetElement, SSIDElement};
use ieee80211::mgmt_frame::body::BeaconBody;
use ieee80211::mgmt_frame::header::ManagementFrameHeader;
use ieee80211::mgmt_frame::BeaconFrame;
use ieee80211::scroll::ctx::MeasureWith;
use ieee80211::scroll::Pwrite;
use ieee80211::{element_chain, supported_rates};
use sys::rs_tx_smart_frame;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub mod sys {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

static HELLO_ESP32: &'static [u8] = b"Hello ESP-RS. https://github.com/esp-rs\0";

#[no_mangle]
pub extern "C" fn hello() -> *const c_void {
    HELLO_ESP32.as_ptr() as *const c_void
}

pub fn get_next_mac_event(timeout_ms: u32) -> Option<u32> {
    let mut type_: u32 = 0;
    let mut data: usize = 0;
    let mut data_ptr = &mut data as *mut usize as *mut c_void; // cast &mut x to usize ptr (which it is) then cast that to a void *
    let res = unsafe {
        sys::rs_get_next_mac_event_raw(timeout_ms, &mut type_, &mut data_ptr as *mut *mut c_void)
    };
    if res {
        Some(type_)
    } else {
        None
    }
}

#[no_mangle]
pub extern "C" fn rust_mac_task() -> *const c_void {
    loop {
        get_next_mac_event(100);
        let MAC_ADDRESS = [0x00, 0x23, 0x45, 0x67, 0x89, 0xab];
        let SSID = "hi";
        let beacon = BeaconFrame {
            header: ManagementFrameHeader {
                fcf_flags: FCFFlags::new(),
                duration: 0,
                receiver_address: [0xff; 6].into(),
                transmitter_address: MAC_ADDRESS.into(),
                bssid: MAC_ADDRESS.into(),
                ..Default::default()
            },
            body: BeaconBody {
                timestamp: 0,
                // We transmit a beacon every 100 ms/TUs
                beacon_interval: 100,
                capabilities_info: CapabilitiesInformation::new().with_is_ess(true),
                elements: element_chain! {
                    SSIDElement::new(SSID).unwrap(),
                    // These are known good values.
                    supported_rates![
                        1 B,
                        2 B,
                        5.5 B,
                        11 B,
                        6,
                        9,
                        12,
                        18
                    ],
                    DSSSParameterSetElement {
                        current_channel: 1,
                    }
                },
                _phantom: PhantomData,
            },
        };
        let length = beacon.measure_with(&true);
        let smart_frame = unsafe { sys::rs_get_smart_frame(length) }; // TODO wrap this and handle failure
        unsafe {
            (*smart_frame).payload_length = length;
            (*smart_frame).rate = 0x0C;
        };
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                (*smart_frame).payload,
                (*smart_frame).payload_size as usize,
            )
        };
        buf.pwrite(beacon, 0).unwrap();

        unsafe { sys::rs_tx_smart_frame(smart_frame) };
    }
}
