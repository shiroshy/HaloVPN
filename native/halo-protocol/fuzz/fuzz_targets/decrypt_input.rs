#![no_main]

use halo_protocol::halo_session_decrypt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let prefix_length = data.len().min(24);
    let mut output = [0_u8; 1400];
    let mut output_length = 0_usize;
    // SAFETY: All slices and output storage remain valid for the call; the invalid handle is intentional fuzz input.
    let _ = unsafe { halo_session_decrypt(
        u64::MAX,
        0,
        data.as_ptr(),
        prefix_length,
        data.as_ptr(),
        data.len(),
        output.as_mut_ptr(),
        output.len(),
        &mut output_length,
    ) };
});
