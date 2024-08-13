#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::c_void;
use core::panic::PanicInfo;

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

pub fn get_next_mac_event() -> Option<u32> {
    let mut type_: u32 = 0;
    let mut data: usize = 0;
    let mut data_ptr = &mut data as *mut usize as *mut c_void; // cast &mut x to usize ptr (which it is) then cast that to a void *
    let res = unsafe {
        sys::rs_get_next_mac_event_raw(32, &mut type_, &mut data_ptr as *mut *mut c_void)
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
        get_next_mac_event();
    }
}
