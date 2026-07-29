#![no_main]

use halo_protocol::{halo_session_create_client, halo_session_encrypt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let declared = data
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(usize::from_le_bytes)
        .unwrap_or(usize::MAX);
    let mut handle = 0_u64;
    // SAFETY: Null pointers are intentional; the ABI must reject inconsistent declared lengths before dereference.
    let _ = unsafe { halo_session_create_client(
        std::ptr::null(),
        declared,
        std::ptr::null(),
        declared,
        &mut handle,
    ) };
    let mut output_length = 0_usize;
    // SAFETY: Null pointers and adversarial lengths are intentional ABI validation inputs.
    let _ = unsafe { halo_session_encrypt(
        u64::MAX,
        0,
        std::ptr::null(),
        declared,
        std::ptr::null_mut(),
        declared,
        &mut output_length,
    ) };
});
