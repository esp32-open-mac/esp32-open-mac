#![no_std]

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use ieee80211::common::{
    CapabilitiesInformation, FCFFlags, IEEE80211AuthenticationAlgorithmNumber, IEEE80211StatusCode,
};
use ieee80211::data_frame::DataFrame;
use ieee80211::elements::element_chain::ElementChainEnd;
use ieee80211::elements::{DSSSParameterSetElement, SSIDElement};
use ieee80211::mgmt_frame::body::{AuthenticationBody, BeaconBody};
use ieee80211::mgmt_frame::{
    AuthenticationFrame, BeaconFrame, DeauthenticationFrame, ManagementFrameHeader,
};
use ieee80211::scroll::ctx::{MeasureWith, TryIntoCtx};
use ieee80211::scroll::Pwrite;
use ieee80211::{element_chain, match_frames, supported_rates};
use sys::{dma_list_item, rs_event_type_t, rs_get_smart_frame, rs_rx_frame_t, rs_tx_smart_frame};

use esp_println as _;
use esp_println::println;

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

pub struct RxFrameWrapper {
    ptr: NonNull<dma_list_item>,
}

impl RxFrameWrapper {
    pub fn dma(&mut self) -> &mut dma_list_item {
        unsafe { self.ptr.as_mut() }
    }

    pub fn payload(&mut self) -> &[u8] {
        let dma = self.dma();
        let packet = unsafe { dma.packet.as_mut().unwrap() };

        unsafe {
            packet
                .payload
                .as_mut_slice(packet.rx_ctrl.sig_len() as usize)
        }
    }
}

pub enum MacEvent {
    PhyRx(RxFrameWrapper),
    MacTx(),
    MacRecycleRx(),
}

impl Drop for RxFrameWrapper {
    fn drop(&mut self) {
        unsafe {
            sys::rs_recycle_dma_item(self.dma());
        }
    }
}

pub fn get_next_mac_event(timeout_ms: u32) -> Option<MacEvent> {
    let mut event_type: rs_event_type_t = rs_event_type_t::EVENT_TYPE_MAC_FREE_RX_DATA;
    let mut data: usize = 0;
    let mut data_ptr = &mut data as *mut usize as *mut c_void; // cast &mut data to usize ptr (which it is) then cast that to a void *
    let res = unsafe {
        sys::rs_get_next_mac_event_raw(
            timeout_ms,
            &mut event_type,
            &mut data_ptr as *mut *mut c_void,
        )
    };
    if !res {
        return None;
    }
    match event_type {
        rs_event_type_t::EVENT_TYPE_PHY_RX_DATA => {
            let wrapper: RxFrameWrapper = RxFrameWrapper {
                ptr: NonNull::new(data_ptr as *mut dma_list_item).unwrap(),
            };
            return Some(MacEvent::PhyRx(wrapper));
        }
        _ => return None,
    }
}

pub fn transmit_frame<
    Frame: MeasureWith<bool> + TryIntoCtx<bool, Error = ieee80211::scroll::Error>,
>(
    frame: Frame,
    rate: u32,
) -> Result<(), Frame> {
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

    unsafe { rs_tx_smart_frame(smart_frame) };

    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_mac_task() -> *const c_void {
    loop {
        let a = get_next_mac_event(10000);
        match a {
            Some(event) => match event {
                MacEvent::PhyRx(mut wrapper) => {
                    println!("RX frame");
                    let payload = wrapper.payload();
                    match_frames! {
                        payload,
                        beacon_frame = BeaconFrame => {
                            println!("SSID: {}", beacon_frame.body.ssid().unwrap());
                        }
                        _ = DeauthenticationFrame => {}
                        _ = DataFrame => {}
                    }
                    .unwrap();
                }
                _ => {
                    println!("other event")
                }
            },
            None => {}
        }
        let mac_address = [0x00, 0x23, 0x45, 0x67, 0x89, 0xab];
        let ssid = "hi";
        println!("transmitting!!");

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
