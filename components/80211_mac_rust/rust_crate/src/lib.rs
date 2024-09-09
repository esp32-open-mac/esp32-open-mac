#![no_std]

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use ieee80211::common::{
    CapabilitiesInformation, FCFFlags, IEEE80211AuthenticationAlgorithmNumber, IEEE80211StatusCode,
};
use ieee80211::data_frame::DataFrame;
use ieee80211::elements::element_chain::ElementChainEnd;
use ieee80211::elements::rsn::RSNElement;
use ieee80211::elements::{DSSSParameterSetElement, SSIDElement};
use ieee80211::mac_parser::{MACAddress, BROADCAST};
use ieee80211::mgmt_frame::body::{AssociationRequestBody, AuthenticationBody, BeaconBody};
use ieee80211::mgmt_frame::{
    AssociationRequestFrame, AssociationResponseFrame, AuthenticationFrame, BeaconFrame,
    DeauthenticationFrame, ManagementFrameHeader,
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

// network we can connect to
pub enum KnownNetwork<'a> {
    OpenNetwork(&'a str), // TODO WPA/...
}

const NETWORK_TO_CONNECT: KnownNetwork = KnownNetwork::OpenNetwork("test");

#[derive(Debug, PartialEq, Eq)]
struct AuthenticateS {
    last_sent: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
struct AssociateS {
    last_sent: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum StaMachineState {
    Scanning,
    Authenticate(AuthenticateS),
    Associate(AssociateS),
    Associated,
}

// holds all state for the case where we are a station
// TODO find better name for this and for the StaMachineState
struct STAState {
    own_mac: MACAddress,
    bssid: MACAddress,
    state: StaMachineState,
}

fn handle_beacon(state: &mut STAState, beacon_frame: BeaconFrame) {
    let Some(ssid) = beacon_frame.ssid() else {
        return; // no SSID in beacon frame
    };

    match NETWORK_TO_CONNECT {
        KnownNetwork::OpenNetwork(ssid_to_connect) => {
            // TODO: I don't think RSNElement is the only way a beacon makes it known that you need to authenticate
            let None = beacon_frame.elements.get_first_element::<RSNElement>() else {
                return; // there shouldn't be an RSN element for open network
            };
            if ssid_to_connect != ssid {
                return;
            }
            // SSID matches and no security
            // TODO save MAC address and set state
            // TODO enable filters 
            if state.state == StaMachineState::Scanning {
                state.bssid = beacon_frame.header.bssid;
                state.state = StaMachineState::Authenticate(AuthenticateS { last_sent: None });
            }
        }
    }
}

fn handle_auth(state: &mut STAState, auth_frame: AuthenticationFrame) {
    // I guess we should validate the MAC address; TODO

    match NETWORK_TO_CONNECT {
        KnownNetwork::OpenNetwork(_) => {
            if (auth_frame.authentication_algorithm_number
                == IEEE80211AuthenticationAlgorithmNumber::OpenSystem)
                && auth_frame.status_code == IEEE80211StatusCode::Success
            {
                // station accepted our authentication
                // transition to association
                state.state = StaMachineState::Associate(AssociateS { last_sent: None });
            }
        }
    }
}

fn handle_assoc_resp(state: &mut STAState, assoc_resp_frame: AssociationResponseFrame) {
    if assoc_resp_frame.body.status_code == IEEE80211StatusCode::Success {
        // yay, they accepted our association
        state.state = StaMachineState::Associated;
        // TODO let network adapter know the network is up
    }
}

const AUTHENTICATE_INTERVAL_MS: u64 = 500;
const ASSOCIATE_INTERVAL_MS: u64 = 500;

fn get_time_us() -> u64 {
    1 // TODO
}

fn send_authenticate(state: &mut STAState) {
    let auth = AuthenticationFrame {
        header: ManagementFrameHeader {
            fcf_flags: FCFFlags::new(),
            duration: 0, // TODO
            receiver_address: state.bssid,
            transmitter_address: state.own_mac,
            bssid: state.bssid,
            ..Default::default()
        },
        body: AuthenticationBody {
            authentication_algorithm_number: IEEE80211AuthenticationAlgorithmNumber::OpenSystem,
            authentication_transaction_sequence_number: 1,
            status_code: IEEE80211StatusCode::Success,
            elements: element_chain!(),
            _phantom: PhantomData,
        },
    };
    transmit_frame(auth, 12).unwrap();
    // update last sent timer
    if let StaMachineState::Authenticate(s) = &mut state.state {
        s.last_sent = Some(get_time_us());
    };
}

fn send_associate(state: &mut STAState) {
    let assoc = AssociationRequestFrame {
        header: ManagementFrameHeader {
            fcf_flags: FCFFlags::new(),
            duration: 0, // TODO
            receiver_address: state.bssid,
            transmitter_address: state.own_mac,
            bssid: state.bssid,
            ..Default::default()
        },
        body: AssociationRequestBody {
            elements: element_chain!(),
            capabilities_info: CapabilitiesInformation::new().with_is_ess(true),
            listen_interval: 0,
            _phantom: PhantomData,
        },
    };
    transmit_frame(assoc, 12).unwrap();
    // update last sent timer
    if let StaMachineState::Associate(s) = &mut state.state {
        s.last_sent = Some(get_time_us());
    };
}

// handles whatever we need to do with the current state, then return the amount of ms to wait if no external events happen
fn handle_state(state: &mut STAState) -> u32 {
    // TODO
    match &state.state {
        StaMachineState::Scanning => 10000,
        StaMachineState::Authenticate(s) => {
            let time_to_wait: u64 = s
                .last_sent
                .map(|t| ((t + AUTHENTICATE_INTERVAL_MS) - get_time_us()))
                .unwrap_or(0);
            if time_to_wait <= 0 {
                send_authenticate(state);
                return AUTHENTICATE_INTERVAL_MS.try_into().unwrap();
            } else {
                return time_to_wait.try_into().unwrap_or(u32::MAX);
            }
        }
        StaMachineState::Associate(s) => {
            let time_to_wait: u64 = s
                .last_sent
                .map(|t| ((t + ASSOCIATE_INTERVAL_MS) - get_time_us()))
                .unwrap_or(0);
            if time_to_wait <= 0 {
                send_associate(state);
                return ASSOCIATE_INTERVAL_MS.try_into().unwrap();
            } else {
                return time_to_wait.try_into().unwrap_or(u32::MAX);
            }
        }
        _default => 10000,
    }
}

#[no_mangle]
pub extern "C" fn rust_mac_task() -> *const c_void {
    let mut state: STAState = STAState {
        bssid: BROADCAST,
        state: StaMachineState::Scanning,
        own_mac: MACAddress([0x00, 0x23, 0x45, 0x67, 0x89, 0xab]), // TODO don't hardcode this
    };

    loop {
        let wait_for = handle_state(&mut state);

        let a = get_next_mac_event(wait_for);
        match a {
            Some(event) => match event {
                MacEvent::PhyRx(mut wrapper) => {
                    println!("RX frame");
                    let payload = wrapper.payload();
                    match_frames! {
                        payload,
                        beacon_frame = BeaconFrame => {
                            handle_beacon(&mut state, beacon_frame)
                        }
                        auth_frame = AuthenticationFrame => {
                            handle_auth(&mut state, auth_frame)
                        }
                        assoc_resp_frame = AssociationResponseFrame => {
                            handle_assoc_resp(&mut state, assoc_resp_frame)
                        }
                        _data_frame = DataFrame => {
                            // TODO
                        }
                        _ = DeauthenticationFrame => {
                            // TODO
                        }
                    }
                    .unwrap_or_default();
                }
                _ => {
                    println!("other event")
                }
            },
            None => {}
        }
    }
}
