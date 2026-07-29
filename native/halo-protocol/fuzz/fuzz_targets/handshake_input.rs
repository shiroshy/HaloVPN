#![no_main]

use halo_protocol::halo_session_read_handshake;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SAFETY: `data` remains readable for the call and the deliberately invalid handle is validated by the ABI.
    let _ = unsafe { halo_session_read_handshake(u64::MAX, data.as_ptr(), data.len()) };
});
