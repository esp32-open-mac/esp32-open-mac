#![no_std]

use core::ffi::c_void;
use core::marker::PhantomData;

use ieee80211::common::{CapabilitiesInformation, FCFFlags};
use ieee80211::elements::{DSSSParameterSetElement, SSIDElement};
use ieee80211::mgmt_frame::body::BeaconBody;
use ieee80211::mgmt_frame::header::ManagementFrameHeader;
use ieee80211::mgmt_frame::BeaconFrame;
use ieee80211::scroll::ctx::{MeasureWith, TryIntoCtx};
use ieee80211::scroll::Pwrite;
use ieee80211::{element_chain, supported_rates};
use sys::{rs_get_smart_frame, rs_tx_smart_frame};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub mod sys {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn get_next_mac_event(timeout_ms: u32) -> Option<u32> {
    let mut event_type: u32 = 0;
    let mut data: usize = 0;
    let mut data_ptr = &mut data as *mut usize as *mut c_void; // cast &mut x to usize ptr (which it is) then cast that to a void *
    let res = unsafe {
        sys::rs_get_next_mac_event_raw(timeout_ms, &mut event_type, &mut data_ptr as *mut *mut c_void)
    };
    if res {
        Some(event_type)
    } else {
        None
    }
}

pub fn transmit_frame<Frame: MeasureWith<bool> + TryIntoCtx<bool, Error = ieee80211::scroll::Error>>(frame: Frame, rate: u32) -> Result<(), Frame> {
    let length = frame.measure_with(&true);
    let smart_frame = unsafe { rs_get_smart_frame(length) };

    if smart_frame.is_null() {
        return Err(frame);
    }

    unsafe {
        (*smart_frame).payload_length = length;
        (*smart_frame).rate = rate;
    }
    let buf = unsafe {
        core::slice::from_raw_parts_mut(
            (*smart_frame).payload,
            (*smart_frame).payload_size as usize,
        )
    };
    buf.pwrite(frame, 0).unwrap();

    unsafe {
        rs_tx_smart_frame(smart_frame)
    };

    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_mac_task() -> *const c_void {
    loop {
        get_next_mac_event(100);
        let mac_address = [0x00, 0x23, 0x45, 0x67, 0x89, 0xab];
        let ssid = "hi";
        let beacon = BeaconFrame {
            header: ManagementFrameHeader {
                fcf_flags: FCFFlags::new(),
                duration: 0,
                receiver_address: [0xff; 6].into(),
                transmitter_address: mac_address.into(),
                bssid: mac_address.into(),
                ..Default::default()
            },
            body: BeaconBody {
                timestamp: 0,
                // We transmit a beacon every 100 ms/TUs
                beacon_interval: 100,
                capabilities_info: CapabilitiesInformation::new().with_is_ess(true),
                elements: element_chain! {
                    SSIDElement::new(ssid).unwrap(),
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
        transmit_frame(beacon, 12).unwrap();
    }
}
