#![no_std]

use core::default;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use ether_type::EtherType;
use ieee80211::common::{
    CapabilitiesInformation, FCFFlags, FrameControlField, IEEE80211AuthenticationAlgorithmNumber,
    IEEE80211StatusCode, SequenceControl,
};
use ieee80211::data_frame::header::DataFrameHeader;
use ieee80211::data_frame::{DataFrame, DataFrameReadPayload};
use ieee80211::elements::rsn::RSNElement;
use ieee80211::mac_parser::{MACAddress, BROADCAST};
use ieee80211::mgmt_frame::body::{AssociationRequestBody, AuthenticationBody};
use ieee80211::mgmt_frame::{
    AssociationRequestFrame, AssociationResponseFrame, AuthenticationFrame, BeaconFrame,
    DeauthenticationFrame, DisassociationFrame, ManagementFrameHeader,
};
use ieee80211::scroll::ctx::{MeasureWith, TryIntoCtx};
use ieee80211::scroll::{Pread, Pwrite};
use ieee80211::{element_chain, match_frames, ssid, supported_rates, GenericFrame};
use llc::SnapLlcFrame;
use sys::{
    dma_list_item, rs_change_channel, rs_event_type_t, rs_get_smart_frame, rs_get_time_us,
    rs_tx_smart_frame,
};

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

pub struct HardwareRxDataWrapper {
    ptr: NonNull<dma_list_item>,
}

impl HardwareRxDataWrapper {
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

    pub fn channel(&mut self) -> u8 {
        // This does not work on all packets, apparently
        let dma = self.dma();
        let packet = unsafe { dma.packet.as_mut().unwrap() };

        let channel: u8 = packet.rx_ctrl.channel() as u8;
        match packet.rx_ctrl.secondary_channel() {
            0 => channel,
            1 => channel + 1,
            2 => channel - 1,
            _ => {
                panic!("should be either equal, above or below")
            }
        }
    }
}

impl Drop for HardwareRxDataWrapper {
    fn drop(&mut self) {
        unsafe {
            sys::rs_recycle_dma_item(self.dma());
        }
    }
}

pub struct MacTxDataWrapper {
    frame: *mut u8,
    len: usize,
}

impl Drop for MacTxDataWrapper {
    fn drop(&mut self) {
        unsafe { sys::rs_recycle_mac_tx_data(self.frame) }
    }
}

impl MacTxDataWrapper {
    pub fn destination_mac(&mut self) -> MACAddress {
        // TODO check that frame is big enough!
        unsafe {
            MACAddress(
                core::slice::from_raw_parts(self.frame, 6)
                    .try_into()
                    .unwrap(),
            )
        }
    }

    pub fn source_mac(&mut self) -> MACAddress {
        // TODO check that frame is big enough!
        unsafe {
            MACAddress(
                core::slice::from_raw_parts(self.frame.wrapping_add(6), 6)
                    .try_into()
                    .unwrap(),
            )
        }
    }

    pub fn ether_type(&mut self) -> EtherType {
        // TODO check that frame is big enough!
        unsafe {
            let ether: &[u8] = core::slice::from_raw_parts(self.frame.wrapping_add(6 + 6), 2)
                .try_into()
                .unwrap();
            EtherType::from_bits(((ether[1] as u16) << 8) | ether[0] as u16)
        }
    }

    pub fn payload(&mut self) -> &[u8] {
        // TODO check that frame is big enough!
        unsafe {
            core::slice::from_raw_parts(
                self.frame.wrapping_add(6 + 6 + 2),
                self.len - (6 + 6 + 2) + 1,
            )
            .try_into()
            .unwrap()
        }
    }
}

pub enum MacEvent {
    HardwareRx(HardwareRxDataWrapper),
    MacTx(MacTxDataWrapper),
}

pub fn get_next_mac_event(timeout_ms: u32) -> Option<MacEvent> {
    let mut event_type: rs_event_type_t = rs_event_type_t::EVENT_TYPE_MAC_FREE_RX_DATA;
    let mut data: usize = 0;
    let mut data_ptr = &mut data as *mut usize as *mut c_void; // cast &mut data to usize ptr (which it is) then cast that to a void *
    let mut len: usize = 0;
    let res = unsafe {
        sys::rs_get_next_mac_event_raw(
            timeout_ms,
            &mut event_type,
            &mut data_ptr as *mut *mut c_void,
            &mut len,
        )
    };
    if !res {
        return None;
    }
    match event_type {
        rs_event_type_t::EVENT_TYPE_PHY_RX_DATA => {
            let wrapper: HardwareRxDataWrapper = HardwareRxDataWrapper {
                ptr: NonNull::new(data_ptr as *mut dma_list_item).unwrap(),
            };
            return Some(MacEvent::HardwareRx(wrapper));
        }
        rs_event_type_t::EVENT_TYPE_MAC_TX_DATA_FRAME => {
            let wrapper: MacTxDataWrapper = MacTxDataWrapper {
                frame: data_ptr as *mut u8,
                len,
            };
            return Some(MacEvent::MacTx(wrapper));
        }
        _ => return None,
    }
}

pub fn transmit_hardware_frame<
    Frame: MeasureWith<bool> + TryIntoCtx<bool, Error = ieee80211::scroll::Error>,
>(
    frame: Frame,
    rate: u32,
) -> Result<(), ()> {
    let length = frame.measure_with(&true);
    let smart_frame = unsafe { rs_get_smart_frame(length) };

    if smart_frame.is_null() {
        return Err(());
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

fn receive_mac_frame(
    source: MACAddress,
    destination: MACAddress,
    ether_type: EtherType,
    payload: &[u8],
) -> Result<(), ()> {
    let total_length: usize = 6 + 6 + 2 + payload.len();
    let buffer = unsafe { sys::rs_get_mac_rx_frame(total_length) };

    if buffer.is_null() {
        return Err(());
    }

    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, total_length) };

    buffer.pwrite(destination, 0).unwrap();
    buffer.pwrite(source, 6).unwrap();
    buffer.pwrite(ether_type.into_bits(), 6 + 6).unwrap();
    buffer.pwrite(payload, 6 + 6 + 2).unwrap();

    unsafe { sys::rs_rx_mac_frame(buffer.as_mut_ptr(), buffer.len()) };
    Ok(())
}

pub fn get_time_us() -> i64 {
    return unsafe { rs_get_time_us() };
}

// network we can connect to
pub enum KnownNetwork<'a> {
    OpenNetwork(&'a str), // TODO WPA/...
}

const NETWORK_TO_CONNECT: KnownNetwork = KnownNetwork::OpenNetwork("meshtest");

#[derive(Debug, PartialEq, Eq)]
struct AuthenticateS {
    last_sent: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
struct AssociateS {
    last_sent: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
struct ScanningS {
    last_channel_change: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
enum StaMachineState {
    Scanning(ScanningS),
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
    current_channel: u8,

    // sequence control is done per transmitter/receiver combination
    // this is only valid for the `bssid`/`own_mac` for now
    sequence_control_bitmap: u32, // bitmap has 32 bits
    sequence_control_last_seqno: i32,
}

const SEQNO_WINDOW_SIZE: i32 = 32;

fn transition_to_scanning(state: &mut STAState) {
    unsafe { sys::rs_mark_iface_down() }
    unsafe { sys::rs_filters_set_scanning() }
    state.state = StaMachineState::Scanning(ScanningS {
        last_channel_change: None,
    });
}

fn transition_to_authenticating(state: &mut STAState, bssid: MACAddress, _channel: u8) {
    println!("transitioning to authenticating");
    unsafe {
        sys::rs_filters_set_client_with_bssid(bssid.as_ptr());
    }
    // TODO change to correct channel
    // unsafe {rs_change_channel(channel)};
    state.bssid = bssid;
    state.state = StaMachineState::Authenticate(AuthenticateS { last_sent: None });
}

fn handle_beacon(state: &mut STAState, beacon_frame: BeaconFrame, channel: u8) {
    let Some(ssid) = beacon_frame.ssid() else {
        println!("no ssid");
        return; // no SSID in beacon frame
    };
    println!("ssid: {}", ssid);
    match NETWORK_TO_CONNECT {
        KnownNetwork::OpenNetwork(ssid_to_connect) => {
            if ssid_to_connect != ssid {
                println!("ssid '{}' does not match, not connecting", ssid);
                return;
            }
            // TODO: I don't think RSNElement is the only way a beacon makes it known that you need to authenticate
            let None = beacon_frame.elements.get_first_element::<RSNElement>() else {
                println!("network {} has a RSN element, not connecting", ssid);
                return; // there shouldn't be an RSN element for open network
            };

            // SSID matches and no security
            // TODO enable filters
            if let StaMachineState::Scanning(_) = state.state {
                println!("ssid matches, changing to authenticating");
                transition_to_authenticating(state, beacon_frame.header.bssid, channel);
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
                println!("received auth success, transition to associate");
                state.state = StaMachineState::Associate(AssociateS { last_sent: None });
            }
        }
    }
}

fn handle_assoc_resp(state: &mut STAState, assoc_resp_frame: AssociationResponseFrame) {
    if assoc_resp_frame.body.status_code == IEEE80211StatusCode::Success {
        // yay, they accepted our association
        match state.state {
            StaMachineState::Associated => {}
            _ => unsafe { sys::rs_mark_iface_up() },
        }
        state.state = StaMachineState::Associated;
    }
}

fn handle_disassoc(state: &mut STAState, _disassoc_frame: DisassociationFrame) {
    if let StaMachineState::Scanning(_) = state.state {
        return;
    }
    transition_to_scanning(state);
}

fn handle_deauth(state: &mut STAState, _deauth: DeauthenticationFrame) {
    if let StaMachineState::Scanning(_) = state.state {
        return;
    }
    transition_to_scanning(state);
}

fn handle_data_frame(_state: &mut STAState, data_frame: DataFrame) -> Option<()> {
    let payload = data_frame.payload?;
    match payload {
        DataFrameReadPayload::Single(llc) => {
            let llc: Result<SnapLlcFrame, _> = llc.pread(0);
            let Ok(inner_payload) = llc else {
                return None;
            };
            // we now have everything we need, finally
            match (
                data_frame.header.fcf_flags.from_ds(),
                data_frame.header.fcf_flags.to_ds(),
            ) {
                (true, false) => {
                    // Frame from DS
                    let destination: MACAddress = data_frame.header.address_1;
                    let source: MACAddress = data_frame.header.address_3;
                    let ethertype = inner_payload.ether_type;
                    let packet = inner_payload.payload;
                    if let Err(_) = receive_mac_frame(source, destination, ethertype, packet) {
                        println!("Receiving MAC frame failed");
                    }
                }
                _ => {
                    println!(
                        "unhandled data frame from={} to={}",
                        data_frame.header.fcf_flags.from_ds(),
                        data_frame.header.fcf_flags.to_ds()
                    )
                }
            }
        }
        DataFrameReadPayload::AMSDU(_) => {
            println!("AMSDU not handled yet")
        }
    }
    None
}

const AUTHENTICATE_INTERVAL_US: i64 = 500 * 1000;
const ASSOCIATE_INTERVAL_US: i64 = 500 * 1000;

const CHANNEL_HOPPING_INTERVAL_US: i64 = 1500 * 1000;

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
    transmit_hardware_frame(auth, 0x18).unwrap();
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
            elements: element_chain!(ssid!("meshtest"), supported_rates![1.5 B, 2]),
            capabilities_info: CapabilitiesInformation::new().with_is_ess(true),
            listen_interval: 0,
            _phantom: PhantomData,
        },
    };
    transmit_hardware_frame(assoc, 12).unwrap();
    // update last sent timer
    if let StaMachineState::Associate(s) = &mut state.state {
        s.last_sent = Some(get_time_us());
    };
}

fn send_data_frame(state: &mut STAState, wrapper: &mut MacTxDataWrapper) {
    let fcf = FCFFlags::new().with_to_ds(true);

    let dataframe = DataFrame {
        header: DataFrameHeader {
            fcf_flags: fcf,
            duration: 0,                          // TODO
            address_1: state.bssid,               // RA
            address_2: state.own_mac,             // TA
            address_3: wrapper.destination_mac(), // DA
            sequence_control: SequenceControl::new()
                .with_fragment_number(1)
                .with_sequence_number(1), // TODO update these instead of hardcoding
            address_4: None,
            ..Default::default()
        },
        payload: Some(SnapLlcFrame {
            oui: [0, 0, 0],
            ether_type: wrapper.ether_type(),
            payload: wrapper.payload(),
            _phantom: PhantomData,
        }),
        _phantom: PhantomData,
    };
    transmit_hardware_frame(dataframe, 12).unwrap();
}

fn next_channel(channel: u8) -> u8 {
    if channel < 12 {
        return channel + 1;
    }
    return 1;
}

// handles whatever we need to do with the current state, then return the amount of ms to wait if no external events happen
fn handle_state(state: &mut STAState) -> u32 {
    // TODO
    match &mut state.state {
        StaMachineState::Scanning(ref mut s) => {
            if let None = s.last_channel_change {
                println!("setting last ch change to now");
                s.last_channel_change = Some(get_time_us());
            }

            let us_to_wait: i64 = s
                .last_channel_change
                .map(|t| (t + CHANNEL_HOPPING_INTERVAL_US) - get_time_us())
                .unwrap_or(0);

            if us_to_wait <= 0 {
                state.current_channel = next_channel(state.current_channel);
                unsafe { sys::rs_change_channel(state.current_channel) };
                s.last_channel_change = Some(get_time_us());
                return (CHANNEL_HOPPING_INTERVAL_US / 1000) as u32;
            } else {
                let ms_to_wait = (us_to_wait / 1000).try_into().unwrap_or(u32::MAX);
                return ms_to_wait;
            }
        }
        StaMachineState::Authenticate(s) => {
            let us_to_wait: i64 = s
                .last_sent
                .map(|t| (t + AUTHENTICATE_INTERVAL_US) - get_time_us())
                .unwrap_or(0);
            if us_to_wait <= 0 {
                send_authenticate(state);
                return (AUTHENTICATE_INTERVAL_US / 1000) as u32;
            } else {
                let ms_to_wait = (us_to_wait / 1000).try_into().unwrap_or(u32::MAX);
                return ms_to_wait;
            }
        }
        StaMachineState::Associate(s) => {
            let us_to_wait: i64 = s
                .last_sent
                .map(|t| ((t + ASSOCIATE_INTERVAL_US) - get_time_us()))
                .unwrap_or(0);
            if us_to_wait <= 0 {
                println!("sending assoc request");
                send_associate(state);
                return (ASSOCIATE_INTERVAL_US / 1000) as u32;
            } else {
                let ms_to_wait = (us_to_wait / 1000).try_into().unwrap_or(u32::MAX);
                return ms_to_wait;
            }
        }
        _default => 10000,
    }
}

fn sequence_control_accept(
    state: &mut STAState,
    seq: SequenceControl,
    transmitter: MACAddress,
    receiver: MACAddress,
) -> bool {
    if state.bssid != transmitter {
        println!("accepting non-bssid frame");
        return true; // we only know about the bssid
    }
    if state.own_mac != receiver {
        println!("accepting likely broadcast frame");
        return true;
    }

    let seqno_diff = seq.sequence_number() as i32 - state.sequence_control_last_seqno;
    println!(
        "sequence number = {} last = {}, diff = {}",
        seq.sequence_number(),
        state.sequence_control_last_seqno,
        seqno_diff
    );

    if (seqno_diff <= 0 && seqno_diff > -SEQNO_WINDOW_SIZE) {
        // inside the window, slightly older
        if (state.sequence_control_bitmap & (1 << -seqno_diff)) != 0 {
            return false;
        }
        state.sequence_control_bitmap |= 1 << -seqno_diff;
        return true;
    } else if (seqno_diff > 0 && seqno_diff < SEQNO_WINDOW_SIZE) {
        // sequence number is slightly newer
        state.sequence_control_bitmap <<= seqno_diff;
        state.sequence_control_bitmap |= 1;
        state.sequence_control_last_seqno = seq.sequence_number() as i32;
        return true;
    } else if (seqno_diff >= SEQNO_WINDOW_SIZE && seqno_diff < 4095) {
        // sequence number is much newer
        println!("missed a lot of packets ({})", seqno_diff - 1);
        state.sequence_control_bitmap = 1;
        state.sequence_control_last_seqno = seq.sequence_number() as i32;
        return true;
    } else {
        println!("other host may have restarted");
        state.sequence_control_bitmap = 1;
        state.sequence_control_last_seqno = seq.sequence_number() as i32;
        return true;
    }
}

#[no_mangle]
pub extern "C" fn rust_mac_task() -> *const c_void {
    let mut state: STAState = STAState {
        bssid: BROADCAST,
        state: StaMachineState::Scanning(ScanningS {
            last_channel_change: None,
        }),
        own_mac: MACAddress([0x00, 0x23, 0x45, 0x67, 0x89, 0xab]), // TODO don't hardcode this
        current_channel: 1,
        sequence_control_bitmap: 0,
        sequence_control_last_seqno: 0,
    };

    transition_to_scanning(&mut state);

    let mut wait_for: u32 = 0;
    loop {
        let a = get_next_mac_event(wait_for);
        match a {
            Some(event) => {
                wait_for = 0;
                match event {
                    MacEvent::HardwareRx(mut wrapper) => {
                        println!("HardwareRx");
                        let channel = wrapper.channel();
                        println!("channel {}", channel);
                        let payload = wrapper.payload();
                        // let fcf = payload.pread(0).map(FrameControlField::from_bits);
                        // if let Ok(fcf) = fcf {
                        //     println!("type = {:?}", fcf.frame_type());
                        // }

                        let generic = GenericFrame::new(payload, false);
                        let Ok(generic) = generic else {
                            continue;
                        };
                        match (generic.sequence_control(), generic.address_2()) {
                            (Some(seq), Some(ta)) => {
                                if !sequence_control_accept(
                                    &mut state,
                                    seq,
                                    ta,
                                    generic.address_1(),
                                ) {
                                    println!("duplicate frame detected!");
                                    continue;
                                } else {
                                    println!("accepted!");
                                }
                            }
                            _ => (),
                        }

                        let res = match_frames! {
                            payload,
                            beacon_frame = BeaconFrame => {
                                println!("beacon frame");
                                handle_beacon(&mut state, beacon_frame, channel)
                            }
                            auth_frame = AuthenticationFrame => {
                                println!("auth frame");
                                handle_auth(&mut state, auth_frame)
                            }

                            deauth_frame = DeauthenticationFrame => {
                                println!("deauth frame");
                                handle_deauth(&mut state, deauth_frame);
                            }

                            assoc_resp_frame = AssociationResponseFrame => {
                                println!("assoc response");
                                handle_assoc_resp(&mut state, assoc_resp_frame)
                            }

                            disassoc_frame = DisassociationFrame => {
                                println!("disassociation");
                                handle_disassoc(&mut state, disassoc_frame)
                            }

                            data_frame = DataFrame => {
                                println!("data frame");
                                handle_data_frame(&mut state, data_frame);
                            }
                        };
                        match res {
                            Ok(_) => {}
                            Err(a) => {
                                println!("unmatched frame {}", a)
                            }
                        }
                    }
                    MacEvent::MacTx(mut wrapper) => {
                        println!("MacTx");
                        match state.state {
                            StaMachineState::Associated => {
                                send_data_frame(&mut state, &mut wrapper);
                            }
                            _ => {
                                println!("Dropping frame because not yet associated")
                            }
                        }
                    }
                }
            }
            None => {
                wait_for = handle_state(&mut state);
            }
        }
    }
}
