#![no_std]

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use ether_type::EtherType;
use ieee80211::common::{
    AssociationID, CapabilitiesInformation, FCFFlags, FrameControlField, IEEE80211AuthenticationAlgorithmNumber, IEEE80211StatusCode, SequenceControl
};
use ieee80211::data_frame::header::DataFrameHeader;
use ieee80211::data_frame::{DataFrame, DataFrameReadPayload};
use ieee80211::elements::rsn::RSNElement;
use ieee80211::elements::tim::TIMElement;
use ieee80211::elements::{DSSSParameterSetElement, SSIDElement};
use ieee80211::mac_parser::{MACAddress, BROADCAST, ZERO};
use ieee80211::mgmt_frame::body::{AssociationRequestBody, AssociationResponseBody, AuthenticationBody, BeaconBody, ProbeResponseBody};
use ieee80211::mgmt_frame::{
    AssociationRequestFrame, AssociationResponseFrame, AuthenticationFrame, BeaconFrame,
    DeauthenticationFrame, DisassociationFrame, ManagementFrameHeader, ProbeRequestFrame, ProbeResponseFrame,
};
use ieee80211::scroll::ctx::{MeasureWith, TryIntoCtx};
use ieee80211::scroll::{Pread, Pwrite};
use ieee80211::{element_chain, match_frames, ssid, supported_rates, tim_bitmap, GenericFrame};
use llc::SnapLlcFrame;
use sys::{
    dma_list_item, rs_event_type_t, rs_filters_set_ap_mode, rs_get_smart_frame, rs_get_time_us, rs_mac_interface_type_t, rs_tx_smart_frame
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

// network we can connect to
pub enum KnownNetwork<'a> {
    OpenNetwork(&'a str), // TODO WPA/...
}

const NETWORK_TO_CONNECT: KnownNetwork = KnownNetwork::OpenNetwork("meshtest");

const SSID_TO_BROADCAST: &str = "esp32-ap";

const INTERFACE_STA: u8 = 0;
const INTERFACE_AP: u8 = 1;


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

    pub fn interface(&mut self) -> (bool, bool) {
        let dma = self.dma();
        let packet = unsafe { dma.packet.as_mut().unwrap() };

        let filter = packet.rx_ctrl.filter_match();
        ((filter & 0b1) != 0, (filter & 0b10) != 0)
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
    pub fn interface(&mut self) -> u8 {
        unsafe {
            *self.frame
        }
    }

    pub fn destination_mac(&mut self) -> MACAddress {
        // TODO check that frame is big enough!
        unsafe {
            MACAddress(
                core::slice::from_raw_parts(self.frame.wrapping_add(1), 6)
                    .try_into()
                    .unwrap(),
            )
        }
    }

    pub fn source_mac(&mut self) -> MACAddress {
        // TODO check that frame is big enough!
        unsafe {
            MACAddress(
                core::slice::from_raw_parts(self.frame.wrapping_add(1 + 6), 6)
                    .try_into()
                    .unwrap(),
            )
        }
    }

    pub fn ether_type(&mut self) -> EtherType {
        // TODO check that frame is big enough!
        unsafe {
            let ether: &[u8] = core::slice::from_raw_parts(self.frame.wrapping_add(1 + 6 + 6), 2)
                .try_into()
                .unwrap();
            EtherType::from_bits(((ether[1] as u16) << 8) | ether[0] as u16)
        }
    }

    pub fn payload(&mut self) -> &[u8] {
        // TODO check that frame is big enough!
        unsafe {
            core::slice::from_raw_parts(
                self.frame.wrapping_add(1 + 6 + 6 + 2),
                self.len - (1 + 6 + 6 + 2) + 1,
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
            Some(MacEvent::HardwareRx(wrapper))
        }
        rs_event_type_t::EVENT_TYPE_MAC_TX_DATA_FRAME => {
            let wrapper: MacTxDataWrapper = MacTxDataWrapper {
                frame: data_ptr as *mut u8,
                len,
            };
            Some(MacEvent::MacTx(wrapper))
        }
        _ => None,
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
    interface: sys::rs_mac_interface_type_t,
    source: &MACAddress,
    destination: &MACAddress,
    ether_type: EtherType,
    payload: &[u8],
) -> Result<(), ()> {
    let total_length: usize = 6 + 6 + 2 + payload.len();
    let buffer = unsafe { sys::rs_get_mac_rx_frame(total_length) };

    if buffer.is_null() {
        return Err(());
    }

    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, total_length) };

    buffer.pwrite(*destination, 0).unwrap();
    buffer.pwrite(*source, 6).unwrap();
    buffer.pwrite(ether_type.into_bits(), 6 + 6).unwrap();
    buffer.pwrite(payload, 6 + 6 + 2).unwrap();

    unsafe { sys::rs_rx_mac_frame(interface, buffer.as_mut_ptr(), buffer.len()) };
    Ok(())
}

pub fn get_time_us() -> i64 {
    unsafe { rs_get_time_us() }
}

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

#[derive(Debug, PartialEq, Eq)]
enum APClientState {
    Disconnected,
    Authenticated,
    Associated(AssociationID)
}

#[derive(Debug, PartialEq, Eq)]
struct APClient {
    addr: MACAddress,
    last_received_timestamp: i64,
    state: APClientState
}

impl Default for APClient {
    fn default() -> Self {
        APClient {
            addr: ZERO,
            last_received_timestamp: 0,
            state: APClientState::Disconnected,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ApMachineState {
    clients: [APClient; 2],
    last_beacon_timestamp: Option<i64>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct SequenceControlTracker {
    sequence_control_bitmap: u32, // bitmap has 32 bits
    sequence_control_last_seqno: i32,
    mac_address: MACAddress,
}

// holds all state for the case where we are a station
// TODO find better name for this and for the StaMachineState
struct GlobalState {
    iface_1_mac: MACAddress,
    iface_2_mac: MACAddress,
    // TODO separate this BSSID out and into the STA/AP states
    bssid: MACAddress,
    sta_state: StaMachineState,
    ap_state: ApMachineState,
    current_channel: u8,

    // sequence control is done per transmitter/receiver combination
    seq_control_trackers: [SequenceControlTracker; 1]
}

const SEQNO_WINDOW_SIZE: i32 = 32;

fn transition_to_scanning(state: &mut GlobalState) {
    unsafe {
        // TODO don't hardcode this to STA 1
        sys::rs_mark_iface_down(rs_mac_interface_type_t::STA_1_MAC_INTERFACE_TYPE)
    }
    unsafe { sys::rs_filters_set_scanning(INTERFACE_STA, state.iface_1_mac.as_ptr()) }
    state.sta_state = StaMachineState::Scanning(ScanningS {
        last_channel_change: None,
    });
}

fn transition_to_authenticating(state: &mut GlobalState, bssid: MACAddress, _channel: u8) {
    println!("transitioning to authenticating");
    unsafe {
        sys::rs_filters_set_client_with_bssid(INTERFACE_STA, state.iface_1_mac.as_ptr(), bssid.as_ptr());
    }
    // TODO change to correct channel
    state.bssid = bssid;
    state.sta_state = StaMachineState::Authenticate(AuthenticateS { last_sent: None });
}

fn handle_beacon(state: &mut GlobalState, beacon_frame: BeaconFrame, channel: u8) {
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
            if let StaMachineState::Scanning(_) = state.sta_state {
                println!("ssid matches, changing to authenticating");
                transition_to_authenticating(state, beacon_frame.header.bssid, channel);
            }
        }
    }
}

fn handle_sta_auth(state: &mut GlobalState, auth_frame: AuthenticationFrame) {
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
                state.sta_state = StaMachineState::Associate(AssociateS { last_sent: None });
            }
        }
    }
}

fn handle_ap_auth(state: &mut GlobalState, auth_req: AuthenticationFrame) {
    if auth_req.authentication_algorithm_number == IEEE80211AuthenticationAlgorithmNumber::OpenSystem
     && auth_req.authentication_transaction_sequence_number == 0x001
     && auth_req.status_code == IEEE80211StatusCode::Success {
        let auth_resp = AuthenticationFrame {
            header: ManagementFrameHeader {
                fcf_flags: FCFFlags::new(),
                duration: 0, // TODO
                receiver_address: auth_req.header.transmitter_address,
                transmitter_address: state.iface_2_mac,
                bssid: state.iface_2_mac,
                ..Default::default()
            },
            body: AuthenticationBody {
                authentication_algorithm_number: IEEE80211AuthenticationAlgorithmNumber::OpenSystem,
                authentication_transaction_sequence_number: 0x0002,
                status_code: IEEE80211StatusCode::Success,
                elements: element_chain!(),
                _phantom: PhantomData,
            },
        };
        transmit_hardware_frame(auth_resp, 0).unwrap();
    }
}

fn handle_ap_assoc_req(state: &mut GlobalState, assoc_req: AssociationRequestFrame) {
    let ssid = assoc_req.elements.get_matching_elements::<SSIDElement>().next();
    if ssid.is_none_or(|x| x.take_ssid() != SSID_TO_BROADCAST) {
        return;
    }

    // TODO this could be more efficient
    let mut association_id: AssociationID = AssociationID::MIN_AID.into();
    'find_aid: for potential_aid in AssociationID::VALID_AID_RANGE {
        for client in &state.ap_state.clients {
            if let APClientState::Associated(aid) = client.state {
                if aid == potential_aid.into() {
                    continue 'find_aid; 
                }
            }
        }
        association_id = potential_aid.into();
        break;
    }

    // Save client
    for client in state.ap_state.clients.as_mut_slice() {
        match client.state {
            APClientState::Associated(_) => {},
            _ => {
                client.state = APClientState::Associated(association_id);
                client.addr = assoc_req.header.transmitter_address;
                client.last_received_timestamp = get_time_us();
            }
        }
    }

    println!("Associated {:?}", assoc_req.header.transmitter_address);

    let assoc_resp = AssociationResponseFrame {
        header: ManagementFrameHeader {
            fcf_flags: FCFFlags::new(),
            duration: 0, // TODO
            receiver_address: assoc_req.header.transmitter_address,
            transmitter_address: state.iface_2_mac,
            bssid: state.iface_2_mac,
            ..Default::default()
        },
        body: AssociationResponseBody  {
            status_code: IEEE80211StatusCode::Success,
            association_id,
            elements: element_chain! {
                supported_rates![
                    1 B,
                    2 B,
                    5.5 B,
                    11 B,
                    6,
                    9,
                    12,
                    18
                ]
            },
            capabilities_info: CapabilitiesInformation::new().with_is_ess(true),
            _phantom: PhantomData
        }
    };
    transmit_hardware_frame(assoc_resp, 0).unwrap();
}

fn handle_ap_probe_req(state: &mut GlobalState, probe_req: ProbeRequestFrame) {
    let ssid = probe_req.ssid();
    if !ssid.is_none_or(|x| x == SSID_TO_BROADCAST || x.is_empty()) {
        return;
    }
    let probe_response = ProbeResponseFrame {
        header: ManagementFrameHeader {
            fcf_flags: FCFFlags::new(),
            duration: 0, // TODO
            receiver_address: probe_req.header.transmitter_address,
            transmitter_address: state.iface_2_mac,
            bssid: state.iface_2_mac,
            ..Default::default()
        },
        body: ProbeResponseBody {
            timestamp: 0, // TODO hardware overwrites this with zeroes :/
                beacon_interval: (BEACON_INTERVAL_US / 1024) as u16,
                elements: element_chain! {
                    ssid!(SSID_TO_BROADCAST),
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
                        current_channel: state.current_channel
                    },
                    TIMElement {
                        dtim_count: 1,
                        dtim_period: 2,
                        bitmap: Some(tim_bitmap![250]), // TODO replace this with empty TIM once the bug is fixed in ieee80211-rs
                        _phantom: PhantomData
                    }
                },
                capabilities_info: CapabilitiesInformation::new().with_is_ess(true),
                _phantom: PhantomData
        }
    };
    transmit_hardware_frame(probe_response, 0).unwrap();
}

fn handle_assoc_resp(state: &mut GlobalState, assoc_resp_frame: AssociationResponseFrame) {
    if assoc_resp_frame.body.status_code == IEEE80211StatusCode::Success {
        // yay, they accepted our association
        match state.sta_state {
            StaMachineState::Associated => {}
            _ => unsafe {
                // TODO don't hardcode this to STA 1
                sys::rs_mark_iface_up(rs_mac_interface_type_t::STA_1_MAC_INTERFACE_TYPE)
            },
        }
        state.sta_state = StaMachineState::Associated;
        state.seq_control_trackers[0].mac_address = state.bssid;
    }
}

fn handle_disassoc(state: &mut GlobalState, _disassoc_frame: DisassociationFrame) {
    if let StaMachineState::Scanning(_) = state.sta_state {
        return;
    }
    transition_to_scanning(state);
}

fn handle_deauth(state: &mut GlobalState, _deauth: DeauthenticationFrame) {
    if let StaMachineState::Scanning(_) = state.sta_state {
        return;
    }
    transition_to_scanning(state);
}

fn handle_sta_data_frame(_state: &mut GlobalState, data_frame: DataFrame) -> Option<()> {
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
                    let destination: &MACAddress = data_frame.header.destination_address().unwrap();
                    let source: &MACAddress = data_frame.header.source_address().unwrap();
                    let ethertype = inner_payload.ether_type;
                    let packet = inner_payload.payload;
                    // TODO make this dynamic instead of hardcofing STA_1
                    if receive_mac_frame(sys::rs_mac_interface_type_t::STA_1_MAC_INTERFACE_TYPE, source, destination, ethertype, packet).is_err() {
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
fn handle_ap_data_frame(state: &mut GlobalState, data_frame: DataFrame) -> Option<()> {
    let payload = data_frame.payload?;
    let destination: &MACAddress = data_frame.header.destination_address().unwrap();
    for client in &mut state.ap_state.clients {
        if client.addr == *destination {
            client.last_received_timestamp = get_time_us();
        }
    }

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
                (false, true) => {
                    // Frame to DS
                    let destination: &MACAddress = data_frame.header.destination_address().unwrap();
                    let source: &MACAddress = data_frame.header.source_address().unwrap();
                    let ethertype = inner_payload.ether_type;
                    let packet = inner_payload.payload;
                    // TODO make this dynamic instead of hardcoding AP_2
                    // TODO handle transmission of frames to other connected clients?
                    if receive_mac_frame(sys::rs_mac_interface_type_t::AP_2_MAC_INTERFACE_TYPE, source, destination, ethertype, packet).is_err() {
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
const BEACON_INTERVAL_US: i64 = 1024 * 100; // 102.4 ms

const CHANNEL_HOPPING_INTERVAL_US: i64 = 1500 * 1000;

fn send_authenticate(state: &mut GlobalState) {
    let auth = AuthenticationFrame {
        header: ManagementFrameHeader {
            fcf_flags: FCFFlags::new(),
            duration: 0, // TODO
            receiver_address: state.bssid,
            transmitter_address: state.iface_1_mac,
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
    if let StaMachineState::Authenticate(s) = &mut state.sta_state {
        s.last_sent = Some(get_time_us());
    };
}

fn send_associate(state: &mut GlobalState) {
    let assoc = AssociationRequestFrame {
        header: ManagementFrameHeader {
            fcf_flags: FCFFlags::new(),
            duration: 0, // TODO
            receiver_address: state.bssid,
            transmitter_address: state.iface_1_mac,
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
    if let StaMachineState::Associate(s) = &mut state.sta_state {
        s.last_sent = Some(get_time_us());
    };
}

fn send_sta_data_frame(state: &mut GlobalState, wrapper: &mut MacTxDataWrapper) {
    let fcf = FCFFlags::new().with_to_ds(true);

    let dataframe = DataFrame {
        header: DataFrameHeader {
            fcf_flags: fcf,
            duration: 0,                          // TODO
            address_1: state.bssid,               // RA
            address_2: state.iface_1_mac,         // TA
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


fn send_ap_data_frame(state: &mut GlobalState, wrapper: &mut MacTxDataWrapper) {
    let fcf = FCFFlags::new().with_from_ds(true);

    let dataframe = DataFrame {
        header: DataFrameHeader {
            fcf_flags: fcf,
            duration: 0,                          // TODO
            address_1: wrapper.destination_mac(), // RA
            address_2: state.iface_2_mac,         // TA = BSSID
            address_3: wrapper.source_mac(),      // SA
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
    1
}

// handles whatever we need to do with the current state, then return the amount of ms to wait if no external events happen
fn handle_state_sta(state: &mut GlobalState) -> u32 {
    match &mut state.sta_state {
        StaMachineState::Scanning(ref mut s) => {
            if s.last_channel_change.is_none() {
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
                (CHANNEL_HOPPING_INTERVAL_US / 1000) as u32
            } else {
                
                (us_to_wait / 1000).try_into().unwrap_or(u32::MAX)
            }
        }
        StaMachineState::Authenticate(s) => {
            let us_to_wait: i64 = s
                .last_sent
                .map(|t| (t + AUTHENTICATE_INTERVAL_US) - get_time_us())
                .unwrap_or(0);
            if us_to_wait <= 0 {
                send_authenticate(state);
                (AUTHENTICATE_INTERVAL_US / 1000) as u32
            } else {
                
                (us_to_wait / 1000).try_into().unwrap_or(u32::MAX)
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
                (ASSOCIATE_INTERVAL_US / 1000) as u32
            } else {
                
                (us_to_wait / 1000).try_into().unwrap_or(u32::MAX)
            }
        }
        _default => 10000,
    }
}

fn handle_state_ap(state: &mut GlobalState) -> u32 {
    let us_to_wait: i64 = state.ap_state.last_beacon_timestamp
                .map(|t| ((t + BEACON_INTERVAL_US) - get_time_us()))
                .unwrap_or(0);
    if us_to_wait <= 0 {
        println!("sending beacon");
        let beacon = BeaconFrame {
            header: ManagementFrameHeader {
                fcf_flags: FCFFlags::new(),
                duration: 0, // TODO
                receiver_address: BROADCAST,
                transmitter_address: state.iface_2_mac,
                bssid: state.iface_2_mac,
                ..Default::default()
            },
            body: BeaconBody {
                timestamp: 0, // TODO hardware overwrites this with zeroes :/
                beacon_interval: (BEACON_INTERVAL_US / 1024) as u16,
                elements: element_chain! {
                    ssid!(SSID_TO_BROADCAST),
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
                        current_channel: state.current_channel
                    },
                    TIMElement {
                        dtim_count: 1,
                        dtim_period: 2,
                        bitmap: Some(tim_bitmap![250]), // TODO replace this with empty TIM once the bug is fixed in ieee80211-rs
                        _phantom: PhantomData
                    }
                },
                capabilities_info: CapabilitiesInformation::new().with_is_ess(true),
                _phantom: PhantomData,
            }
        };
        transmit_hardware_frame(beacon, 0).unwrap();
        (BEACON_INTERVAL_US / 1000) as u32
    } else {
        (us_to_wait / 1000).try_into().unwrap_or(u32::MAX)
    }
}

fn sequence_control_accept(
    state: &mut GlobalState,
    seq: SequenceControl,
    transmitter: MACAddress,
    receiver: MACAddress,
) -> bool {

    if state.iface_1_mac != receiver && state.iface_2_mac != receiver {
        println!("accepting likely broadcast frame");
        return true;
    }
    for seq_ctrl_tracker in &mut state.seq_control_trackers {
        if seq_ctrl_tracker.mac_address != transmitter {
            continue
        }

        let seqno_diff = seq.sequence_number() as i32 - seq_ctrl_tracker.sequence_control_last_seqno;
        println!(
            "sequence number = {} last = {}, diff = {}",
            seq.sequence_number(),
            seq_ctrl_tracker.sequence_control_last_seqno,
            seqno_diff
        );
    
        if seqno_diff <= 0 && seqno_diff > -SEQNO_WINDOW_SIZE {
            // inside the window, slightly older
            if (seq_ctrl_tracker.sequence_control_bitmap & (1 << -seqno_diff)) != 0 {
                return false;
            }
            seq_ctrl_tracker.sequence_control_bitmap |= 1 << -seqno_diff;
            return true
        } else if seqno_diff > 0 && seqno_diff < SEQNO_WINDOW_SIZE {
            // sequence number is slightly newer
            seq_ctrl_tracker.sequence_control_bitmap <<= seqno_diff;
            seq_ctrl_tracker.sequence_control_bitmap |= 1;
            seq_ctrl_tracker.sequence_control_last_seqno = seq.sequence_number() as i32;
            return true;
        } else if (SEQNO_WINDOW_SIZE..4095).contains(&seqno_diff) {
            // sequence number is much newer
            println!("missed a lot of packets ({})", seqno_diff - 1);
            seq_ctrl_tracker.sequence_control_bitmap = 1;
            seq_ctrl_tracker.sequence_control_last_seqno = seq.sequence_number() as i32;
            return true;
        } else {
            println!("other host may have restarted");
            seq_ctrl_tracker.sequence_control_bitmap = 1;
            seq_ctrl_tracker.sequence_control_last_seqno = seq.sequence_number() as i32;
            return true;
        }
    }
    true
}

fn handle_sta_hardware_rx(state: &mut GlobalState, wrapper: &mut HardwareRxDataWrapper) {
    let channel = wrapper.channel();
    println!("HW STA RX: channel {}", channel);
    let payload = wrapper.payload();

    let res = match_frames! {
        payload,
        beacon_frame = BeaconFrame => {
            println!("beacon frame");
            handle_beacon(state, beacon_frame, channel)
        }
        auth_frame = AuthenticationFrame => {
            println!("auth frame");
            handle_sta_auth(state, auth_frame)
        }

        deauth_frame = DeauthenticationFrame => {
            println!("deauth frame");
            handle_deauth(state, deauth_frame);
        }

        assoc_resp_frame = AssociationResponseFrame => {
            println!("assoc response");
            handle_assoc_resp(state, assoc_resp_frame)
        }

        disassoc_frame = DisassociationFrame => {
            println!("disassociation");
            handle_disassoc(state, disassoc_frame)
        }

        data_frame = DataFrame => {
            println!("data frame");
            handle_sta_data_frame(state, data_frame);
        }
    };
    match res {
        Ok(_) => {}
        Err(a) => {
            let fcf = payload.pread(0).map(FrameControlField::from_bits);
            if let Ok(fcf) = fcf {
                println!("STA parsing error: {:?} {:?}", a, fcf.frame_type());
            }
        }
    }
}

fn handle_ap_hardware_rx(state: &mut GlobalState, wrapper: &mut HardwareRxDataWrapper) {
    let channel = wrapper.channel();
    println!("HW AP RX: channel {}", channel);
    let payload = wrapper.payload();

    let res = match_frames! {
        payload,
        probe_req_frame = ProbeRequestFrame => {
            println!("probe req frame");
            handle_ap_probe_req(state, probe_req_frame);
        }
        auth_frame = AuthenticationFrame => {
            println!("auth frame");
            handle_ap_auth(state, auth_frame)
        }

        assoc_req_frame = AssociationRequestFrame => {
            println!("assoc response");
            handle_ap_assoc_req(state, assoc_req_frame)
        }

        data_frame = DataFrame => {
            println!("data frame");
            handle_ap_data_frame(state, data_frame);
        }
    };
    match res {
        Ok(_) => {}
        Err(a) => {
            let fcf = payload.pread(0).map(FrameControlField::from_bits);
            if let Ok(fcf) = fcf {
                println!("AP parsing error: {:?} {:?}", a, fcf.frame_type());
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_mac_task() -> *const c_void {
    let mut state: GlobalState = GlobalState {
        bssid: BROADCAST,
        sta_state: StaMachineState::Scanning(ScanningS {
            last_channel_change: None,
        }),
        ap_state: ApMachineState {
            clients: Default::default(),
            last_beacon_timestamp: None
        },
        iface_1_mac: MACAddress([0x00, 0x23, 0x45, 0x67, 0x89, 0xab]), // TODO don't hardcode this
        iface_2_mac: MACAddress([0x00, 0x20, 0x91, 0x00, 0x00, 0x00]), // TODO don't hardcode this
        current_channel: 1,
        seq_control_trackers: [SequenceControlTracker::default()]
    };

    unsafe {
        rs_filters_set_ap_mode(1, state.iface_2_mac.as_ptr());
    }
    transition_to_scanning(&mut state);

    let mut wait_for: u32 = 0;
    loop {
        let a = get_next_mac_event(wait_for);
        match a {
            Some(event) => {
                wait_for = 0;
                match event {
                    MacEvent::HardwareRx(mut wrapper) => {
                        let payload = wrapper.payload();
                        let generic = GenericFrame::new(payload, false);
                        let Ok(generic) = generic else {
                            continue;
                        };
                        if let (Some(seq), Some(ta)) = (generic.sequence_control(), generic.address_2()) {
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
                        let matches = wrapper.interface();
                        if matches.0 {
                            handle_sta_hardware_rx(&mut state, &mut wrapper);
                        }
                        if matches.1 {
                            handle_ap_hardware_rx(&mut state, &mut wrapper);
                        }
                    }
                    MacEvent::MacTx(mut wrapper) => {
                        println!("MacTx {:?}", wrapper.interface());
                        if wrapper.interface()  == rs_mac_interface_type_t::STA_1_MAC_INTERFACE_TYPE as u8 {
                            match state.sta_state {
                                StaMachineState::Associated => {
                                    send_sta_data_frame(&mut state, &mut wrapper);
                                }
                                _ => {
                                    println!("Dropping frame because not yet associated")
                                }
                            }
                        }
                        else if wrapper.interface() == rs_mac_interface_type_t::AP_2_MAC_INTERFACE_TYPE as u8 {
                            send_ap_data_frame(&mut state, &mut wrapper);
                        }
                    }
                }
            }
            None => {
                let wait_for_sta = handle_state_sta(&mut state);
                let wait_for_ap = handle_state_ap(&mut state);
                wait_for = wait_for_ap.min(wait_for_sta);
            }
        }
    }
}
