//! Native Noise core and stable C ABI for the Stage 1 laboratory channel.

use snow::{Builder, HandshakeState, StatelessTransportState};
use std::collections::HashMap;
use std::ffi::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const ABI_VERSION: u32 = 1;
pub const WIRE_VERSION: u8 = 0;
pub const COMMON_HEADER_SIZE: usize = 24;
pub const AUTHENTICATION_TAG_SIZE: usize = 16;
pub const MAXIMUM_DATAGRAM_SIZE: usize = 1400;
pub const MAXIMUM_HANDSHAKE_SIZE: usize = 512;
pub const MAXIMUM_PLAINTEXT_SIZE: usize = 1228;
pub const REPLAY_WINDOW_SIZE: usize = 2048;
pub const SESSION_MESSAGE_LIMIT: u64 = 1_u64 << 32;
pub const KEY_SIZE: usize = 32;

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"HaloVPN Stage 1|wire=0|Noise_IK_25519_ChaChaPoly_SHA256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    Success = 0,
    InvalidArgument = 1,
    InvalidState = 2,
    InvalidPacket = 3,
    UnsupportedVersion = 4,
    AuthenticationFailed = 5,
    ReplayDetected = 6,
    CapacityExceeded = 7,
    KeyLimitReached = 8,
    BufferTooSmall = 9,
    InvalidHandle = 10,
    InternalError = 255,
}

impl ErrorCode {
    const fn message(self) -> &'static [u8] {
        match self {
            Self::Success => b"success\0",
            Self::InvalidArgument => b"invalid argument\0",
            Self::InvalidState => b"invalid session state\0",
            Self::InvalidPacket => b"invalid packet\0",
            Self::UnsupportedVersion => b"unsupported version\0",
            Self::AuthenticationFailed => b"authentication failed\0",
            Self::ReplayDetected => b"replay or stale packet\0",
            Self::CapacityExceeded => b"capacity exceeded\0",
            Self::KeyLimitReached => b"session message limit reached\0",
            Self::BufferTooSmall => b"output buffer too small\0",
            Self::InvalidHandle => b"invalid or destroyed session handle\0",
            Self::InternalError => b"internal error\0",
        }
    }
}

type Handle = u64;

enum SessionState {
    Handshake(Box<HandshakeState>),
    Transport(Box<StatelessTransportState>),
    Failed,
}

struct Session {
    state: SessionState,
    expected_remote_static: Option<[u8; KEY_SIZE]>,
    next_send: u64,
    replay: ReplayWindow,
}

#[derive(Clone)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: [bool; REPLAY_WINDOW_SIZE],
}

impl ReplayWindow {
    const fn new() -> Self {
        Self {
            highest: None,
            seen: [false; REPLAY_WINDOW_SIZE],
        }
    }

    fn check(&self, packet_number: u64) -> Result<(), ErrorCode> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if packet_number > highest {
            return Ok(());
        }
        let age = highest - packet_number;
        let Ok(age_index) = usize::try_from(age) else {
            return Err(ErrorCode::ReplayDetected);
        };
        if age >= REPLAY_WINDOW_SIZE as u64 || self.seen[age_index] {
            return Err(ErrorCode::ReplayDetected);
        }
        Ok(())
    }

    fn mark(&mut self, packet_number: u64) {
        match self.highest {
            None => {
                self.highest = Some(packet_number);
                self.seen[0] = true;
            }
            Some(highest) if packet_number > highest => {
                let shift = packet_number - highest;
                if shift >= REPLAY_WINDOW_SIZE as u64 {
                    self.seen.fill(false);
                } else {
                    let Ok(shift) = usize::try_from(shift) else {
                        self.seen.fill(false);
                        self.highest = Some(packet_number);
                        self.seen[0] = true;
                        return;
                    };
                    self.seen.copy_within(0..REPLAY_WINDOW_SIZE - shift, shift);
                    self.seen[..shift].fill(false);
                }
                self.highest = Some(packet_number);
                self.seen[0] = true;
            }
            Some(highest) => {
                if let Ok(age) = usize::try_from(highest - packet_number) {
                    self.seen[age] = true;
                }
            }
        }
    }
}

static SESSIONS: OnceLock<Mutex<HashMap<Handle, Session>>> = OnceLock::new();
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn sessions() -> &'static Mutex<HashMap<Handle, Session>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_sessions<T>(
    action: impl FnOnce(&mut HashMap<Handle, Session>) -> Result<T, ErrorCode>,
) -> Result<T, ErrorCode> {
    let mut guard = sessions().lock().map_err(|_| ErrorCode::InternalError)?;
    action(&mut guard)
}

fn noise_builder() -> Result<Builder<'static>, ErrorCode> {
    let params = NOISE_PATTERN
        .parse()
        .map_err(|_| ErrorCode::InternalError)?;
    Builder::new(params)
        .prologue(PROLOGUE)
        .map_err(|_| ErrorCode::InternalError)
}

fn create_client(local_private: &[u8], remote_public: &[u8]) -> Result<Session, ErrorCode> {
    if local_private.len() != KEY_SIZE || remote_public.len() != KEY_SIZE {
        return Err(ErrorCode::InvalidArgument);
    }
    let handshake = noise_builder()?
        .local_private_key(local_private)
        .map_err(|_| ErrorCode::InvalidArgument)?
        .remote_public_key(remote_public)
        .map_err(|_| ErrorCode::InvalidArgument)?
        .build_initiator()
        .map_err(|_| ErrorCode::InvalidArgument)?;
    Ok(Session {
        state: SessionState::Handshake(Box::new(handshake)),
        expected_remote_static: None,
        next_send: 0,
        replay: ReplayWindow::new(),
    })
}

fn create_server(local_private: &[u8], allowed_client_public: &[u8]) -> Result<Session, ErrorCode> {
    if local_private.len() != KEY_SIZE || allowed_client_public.len() != KEY_SIZE {
        return Err(ErrorCode::InvalidArgument);
    }
    let handshake = noise_builder()?
        .local_private_key(local_private)
        .map_err(|_| ErrorCode::InvalidArgument)?
        .build_responder()
        .map_err(|_| ErrorCode::InvalidArgument)?;
    let mut expected = [0_u8; KEY_SIZE];
    expected.copy_from_slice(allowed_client_public);
    Ok(Session {
        state: SessionState::Handshake(Box::new(handshake)),
        expected_remote_static: Some(expected),
        next_send: 0,
        replay: ReplayWindow::new(),
    })
}

fn insert_session(session: Session) -> Result<Handle, ErrorCode> {
    let handle = NEXT_HANDLE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| ErrorCode::CapacityExceeded)?;
    with_sessions(|map| {
        if map.len() >= 1024 {
            return Err(ErrorCode::CapacityExceeded);
        }
        map.insert(handle, session);
        Ok(handle)
    })
}

fn promote_if_finished(session: &mut Session) -> Result<(), ErrorCode> {
    let finished =
        matches!(&session.state, SessionState::Handshake(h) if h.is_handshake_finished());
    if !finished {
        return Ok(());
    }
    let state = std::mem::replace(&mut session.state, SessionState::Failed);
    let SessionState::Handshake(handshake) = state else {
        return Err(ErrorCode::InternalError);
    };
    let transport = (*handshake)
        .into_stateless_transport_mode()
        .map_err(|_| ErrorCode::InternalError)?;
    session.state = SessionState::Transport(Box::new(transport));
    Ok(())
}

fn write_handshake(session: &mut Session, output: &mut [u8]) -> Result<usize, ErrorCode> {
    if output.len() < MAXIMUM_HANDSHAKE_SIZE {
        return Err(ErrorCode::BufferTooSmall);
    }
    let SessionState::Handshake(handshake) = &mut session.state else {
        return Err(ErrorCode::InvalidState);
    };
    if !handshake.is_my_turn() {
        return Err(ErrorCode::InvalidState);
    }
    let written = handshake
        .write_message(&[], output)
        .map_err(|_| ErrorCode::InvalidState)?;
    promote_if_finished(session)?;
    Ok(written)
}

fn read_handshake(session: &mut Session, input: &[u8]) -> Result<(), ErrorCode> {
    if input.is_empty() || input.len() > MAXIMUM_HANDSHAKE_SIZE {
        return Err(ErrorCode::InvalidPacket);
    }
    let SessionState::Handshake(handshake) = &mut session.state else {
        return Err(ErrorCode::InvalidState);
    };
    if handshake.is_my_turn() {
        return Err(ErrorCode::InvalidState);
    }
    let mut payload = [0_u8; 1];
    let payload_len = handshake
        .read_message(input, &mut payload)
        .map_err(|_| ErrorCode::AuthenticationFailed)?;
    if payload_len != 0 {
        session.state = SessionState::Failed;
        return Err(ErrorCode::InvalidPacket);
    }
    if let Some(expected) = session.expected_remote_static {
        let authenticated = handshake
            .get_remote_static()
            .is_some_and(|remote| remote.len() == KEY_SIZE && remote.ct_eq(&expected).into());
        if !authenticated {
            session.state = SessionState::Failed;
            return Err(ErrorCode::AuthenticationFailed);
        }
    }
    promote_if_finished(session)
}

fn encrypt(
    session: &mut Session,
    packet_number: u64,
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, ErrorCode> {
    if plaintext.len() > MAXIMUM_PLAINTEXT_SIZE {
        return Err(ErrorCode::InvalidArgument);
    }
    if packet_number >= SESSION_MESSAGE_LIMIT || session.next_send >= SESSION_MESSAGE_LIMIT {
        return Err(ErrorCode::KeyLimitReached);
    }
    if packet_number != session.next_send {
        return Err(ErrorCode::InvalidState);
    }
    let needed = plaintext
        .len()
        .checked_add(AUTHENTICATION_TAG_SIZE)
        .ok_or(ErrorCode::InvalidArgument)?;
    if output.len() < needed {
        return Err(ErrorCode::BufferTooSmall);
    }
    let SessionState::Transport(transport) = &session.state else {
        return Err(ErrorCode::InvalidState);
    };
    let written = transport
        .write_message(packet_number, plaintext, output)
        .map_err(|_| ErrorCode::InternalError)?;
    session.next_send = session
        .next_send
        .checked_add(1)
        .ok_or(ErrorCode::KeyLimitReached)?;
    Ok(written)
}

fn decrypt(
    session: &mut Session,
    packet_number: u64,
    expected_prefix: &[u8],
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, ErrorCode> {
    if packet_number >= SESSION_MESSAGE_LIMIT {
        return Err(ErrorCode::KeyLimitReached);
    }
    if ciphertext.len() < AUTHENTICATION_TAG_SIZE || ciphertext.len() > MAXIMUM_DATAGRAM_SIZE {
        return Err(ErrorCode::InvalidPacket);
    }
    session.replay.check(packet_number)?;
    let needed = ciphertext.len() - AUTHENTICATION_TAG_SIZE;
    if output.len() < needed {
        return Err(ErrorCode::BufferTooSmall);
    }
    let SessionState::Transport(transport) = &session.state else {
        return Err(ErrorCode::InvalidState);
    };
    let written = transport
        .read_message(packet_number, ciphertext, output)
        .map_err(|_| ErrorCode::AuthenticationFailed)?;
    if written < expected_prefix.len()
        || !bool::from(output[..expected_prefix.len()].ct_eq(expected_prefix))
    {
        output[..written].fill(0);
        return Err(ErrorCode::AuthenticationFailed);
    }
    session.replay.mark(packet_number);
    Ok(written)
}

fn ffi_boundary(action: impl FnOnce() -> Result<(), ErrorCode>) -> u32 {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(())) => ErrorCode::Success as u32,
        Ok(Err(code)) => code as u32,
        Err(_) => ErrorCode::InternalError as u32,
    }
}

unsafe fn input_slice<'a>(
    pointer: *const u8,
    length: usize,
    maximum: usize,
) -> Result<&'a [u8], ErrorCode> {
    if length > maximum || (length != 0 && pointer.is_null()) {
        return Err(ErrorCode::InvalidArgument);
    }
    if length == 0 {
        return Ok(&[]);
    }
    // SAFETY: The caller contract supplies a readable buffer of `length` bytes; null and bounds were checked above.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

unsafe fn output_slice<'a>(
    pointer: *mut u8,
    length: usize,
    maximum: usize,
) -> Result<&'a mut [u8], ErrorCode> {
    if length > maximum || (length != 0 && pointer.is_null()) {
        return Err(ErrorCode::InvalidArgument);
    }
    if length == 0 {
        return Ok(&mut []);
    }
    // SAFETY: The caller contract supplies an exclusive writable buffer of `length` bytes; null and bounds were checked above.
    Ok(unsafe { slice::from_raw_parts_mut(pointer, length) })
}

fn set_usize(pointer: *mut usize, value: usize) -> Result<(), ErrorCode> {
    if pointer.is_null() {
        return Err(ErrorCode::InvalidArgument);
    }
    // SAFETY: The non-null pointer is caller-owned and points to one writable `usize` by ABI contract.
    unsafe {
        pointer.write(value);
    }
    Ok(())
}

fn set_u64(pointer: *mut u64, value: u64) -> Result<(), ErrorCode> {
    if pointer.is_null() {
        return Err(ErrorCode::InvalidArgument);
    }
    // SAFETY: The non-null pointer is caller-owned and points to one writable `u64` by ABI contract.
    unsafe {
        pointer.write(value);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn halo_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
/// Creates an initiator session.
///
/// # Safety
/// Key pointers must be readable for their declared lengths and `handle` must point to writable `u64` storage.
pub unsafe extern "C" fn halo_session_create_client(
    local_private: *const u8,
    local_len: usize,
    remote_public: *const u8,
    remote_len: usize,
    handle: *mut u64,
) -> u32 {
    ffi_boundary(|| {
        // SAFETY: Validated and borrowed only for this call.
        let local = unsafe { input_slice(local_private, local_len, KEY_SIZE)? };
        // SAFETY: Validated and borrowed only for this call.
        let remote = unsafe { input_slice(remote_public, remote_len, KEY_SIZE)? };
        set_u64(handle, insert_session(create_client(local, remote)?)?)
    })
}

#[unsafe(no_mangle)]
/// Creates a responder session.
///
/// # Safety
/// Key pointers must be readable for their declared lengths and `handle` must point to writable `u64` storage.
pub unsafe extern "C" fn halo_session_create_server(
    local_private: *const u8,
    local_len: usize,
    allowed_public: *const u8,
    allowed_len: usize,
    handle: *mut u64,
) -> u32 {
    ffi_boundary(|| {
        // SAFETY: Validated and borrowed only for this call.
        let local = unsafe { input_slice(local_private, local_len, KEY_SIZE)? };
        // SAFETY: Validated and borrowed only for this call.
        let allowed = unsafe { input_slice(allowed_public, allowed_len, KEY_SIZE)? };
        set_u64(handle, insert_session(create_server(local, allowed)?)?)
    })
}

#[unsafe(no_mangle)]
/// Writes the next Noise handshake message.
///
/// # Safety
/// `output` must be writable for `output_capacity`; `output_length` must point to writable `usize` storage.
pub unsafe extern "C" fn halo_session_write_handshake(
    handle: u64,
    output: *mut u8,
    output_capacity: usize,
    output_length: *mut usize,
) -> u32 {
    ffi_boundary(|| {
        set_usize(output_length, MAXIMUM_HANDSHAKE_SIZE)?;
        // SAFETY: Validated and borrowed only for this call.
        let destination = unsafe { output_slice(output, output_capacity, MAXIMUM_HANDSHAKE_SIZE)? };
        let written = with_sessions(|map| {
            write_handshake(
                map.get_mut(&handle).ok_or(ErrorCode::InvalidHandle)?,
                destination,
            )
        })?;
        set_usize(output_length, written)
    })
}

#[unsafe(no_mangle)]
/// Reads the next Noise handshake message.
///
/// # Safety
/// `input` must be readable for `input_length` bytes when that length is nonzero.
pub unsafe extern "C" fn halo_session_read_handshake(
    handle: u64,
    input: *const u8,
    input_length: usize,
) -> u32 {
    ffi_boundary(|| {
        // SAFETY: Validated and borrowed only for this call.
        let message = unsafe { input_slice(input, input_length, MAXIMUM_HANDSHAKE_SIZE)? };
        with_sessions(|map| {
            read_handshake(
                map.get_mut(&handle).ok_or(ErrorCode::InvalidHandle)?,
                message,
            )
        })
    })
}

#[unsafe(no_mangle)]
/// Encrypts one transport payload.
///
/// # Safety
/// Input must be readable, output writable for its capacity, and `output_length` writable for one `usize`.
pub unsafe extern "C" fn halo_session_encrypt(
    handle: u64,
    packet_number: u64,
    plaintext: *const u8,
    plaintext_length: usize,
    output: *mut u8,
    output_capacity: usize,
    output_length: *mut usize,
) -> u32 {
    ffi_boundary(|| {
        let needed = plaintext_length
            .checked_add(AUTHENTICATION_TAG_SIZE)
            .ok_or(ErrorCode::InvalidArgument)?;
        set_usize(output_length, needed)?;
        // SAFETY: Validated and borrowed only for this call.
        let source = unsafe { input_slice(plaintext, plaintext_length, MAXIMUM_PLAINTEXT_SIZE)? };
        // SAFETY: Validated and borrowed only for this call.
        let destination = unsafe { output_slice(output, output_capacity, MAXIMUM_DATAGRAM_SIZE)? };
        let written = with_sessions(|map| {
            encrypt(
                map.get_mut(&handle).ok_or(ErrorCode::InvalidHandle)?,
                packet_number,
                source,
                destination,
            )
        })?;
        set_usize(output_length, written)
    })
}

#[unsafe(no_mangle)]
/// Decrypts and replay-checks one transport payload.
///
/// # Safety
/// Prefix/ciphertext must be readable, output writable for its capacity, and `output_length` writable for one `usize`.
pub unsafe extern "C" fn halo_session_decrypt(
    handle: u64,
    packet_number: u64,
    expected_prefix: *const u8,
    expected_prefix_length: usize,
    ciphertext: *const u8,
    ciphertext_length: usize,
    output: *mut u8,
    output_capacity: usize,
    output_length: *mut usize,
) -> u32 {
    ffi_boundary(|| {
        let needed = ciphertext_length.saturating_sub(AUTHENTICATION_TAG_SIZE);
        set_usize(output_length, needed)?;
        // SAFETY: Validated and borrowed only for this call.
        let prefix =
            unsafe { input_slice(expected_prefix, expected_prefix_length, COMMON_HEADER_SIZE)? };
        // SAFETY: Validated and borrowed only for this call.
        let source = unsafe { input_slice(ciphertext, ciphertext_length, MAXIMUM_DATAGRAM_SIZE)? };
        // SAFETY: Validated and borrowed only for this call.
        let destination = unsafe { output_slice(output, output_capacity, MAXIMUM_PLAINTEXT_SIZE)? };
        let written = with_sessions(|map| {
            decrypt(
                map.get_mut(&handle).ok_or(ErrorCode::InvalidHandle)?,
                packet_number,
                prefix,
                source,
                destination,
            )
        })?;
        set_usize(output_length, written)
    })
}

#[unsafe(no_mangle)]
/// Reports whether a registered session completed its handshake.
///
/// # Safety
/// `established` must point to one writable byte.
pub unsafe extern "C" fn halo_session_is_established(handle: u64, established: *mut u8) -> u32 {
    ffi_boundary(|| {
        if established.is_null() {
            return Err(ErrorCode::InvalidArgument);
        }
        let value = with_sessions(|map| {
            Ok(u8::from(matches!(
                map.get(&handle).ok_or(ErrorCode::InvalidHandle)?.state,
                SessionState::Transport(_)
            )))
        })?;
        // SAFETY: The non-null pointer is caller-owned and points to one writable byte.
        unsafe {
            established.write(value);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn halo_session_destroy(handle: u64) -> u32 {
    ffi_boundary(|| {
        with_sessions(|map| {
            map.remove(&handle)
                .map(|_| ())
                .ok_or(ErrorCode::InvalidHandle)
        })
    })
}

#[unsafe(no_mangle)]
/// Generates a static X25519 key pair using the resolver CSPRNG.
///
/// # Safety
/// Both output pointers must be writable for their declared capacities.
pub unsafe extern "C" fn halo_generate_keypair(
    private_key: *mut u8,
    private_capacity: usize,
    public_key: *mut u8,
    public_capacity: usize,
) -> u32 {
    ffi_boundary(|| {
        if private_capacity < KEY_SIZE || public_capacity < KEY_SIZE {
            return Err(ErrorCode::BufferTooSmall);
        }
        // SAFETY: Validated and borrowed only for this call.
        let private_out = unsafe { output_slice(private_key, private_capacity, KEY_SIZE)? };
        // SAFETY: Validated and borrowed only for this call.
        let public_out = unsafe { output_slice(public_key, public_capacity, KEY_SIZE)? };
        let keypair = noise_builder()?
            .generate_keypair()
            .map_err(|_| ErrorCode::InternalError)?;
        let private = Zeroizing::new(keypair.private);
        if private.len() != KEY_SIZE || keypair.public.len() != KEY_SIZE {
            return Err(ErrorCode::InternalError);
        }
        private_out[..KEY_SIZE].copy_from_slice(&private);
        public_out[..KEY_SIZE].copy_from_slice(&keypair.public);
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Copies a fixed non-secret error description including its trailing NUL.
///
/// # Safety
/// `output` must be writable for its capacity and `output_length` writable for one `usize`.
pub unsafe extern "C" fn halo_error_message(
    error_code: u32,
    output: *mut c_char,
    output_capacity: usize,
    output_length: *mut usize,
) -> u32 {
    ffi_boundary(|| {
        let code = match error_code {
            0 => ErrorCode::Success,
            1 => ErrorCode::InvalidArgument,
            2 => ErrorCode::InvalidState,
            3 => ErrorCode::InvalidPacket,
            4 => ErrorCode::UnsupportedVersion,
            5 => ErrorCode::AuthenticationFailed,
            6 => ErrorCode::ReplayDetected,
            7 => ErrorCode::CapacityExceeded,
            8 => ErrorCode::KeyLimitReached,
            9 => ErrorCode::BufferTooSmall,
            10 => ErrorCode::InvalidHandle,
            _ => ErrorCode::InternalError,
        };
        let message = code.message();
        set_usize(output_length, message.len())?;
        if output_capacity < message.len() {
            return Err(ErrorCode::BufferTooSmall);
        }
        if output.is_null() {
            return Err(ErrorCode::InvalidArgument);
        }
        // SAFETY: Capacity is sufficient and output is non-null; bytes include a terminating NUL.
        unsafe {
            std::ptr::copy_nonoverlapping(message.as_ptr().cast::<c_char>(), output, message.len());
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let pair = noise_builder()
            .and_then(|b| b.generate_keypair().map_err(|_| ErrorCode::InternalError));
        match pair {
            Ok(pair) => (Zeroizing::new(pair.private), pair.public),
            Err(code) => std::panic::panic_any(code),
        }
    }

    fn established() -> (Session, Session) {
        let (client_private, client_public) = keypair();
        let (server_private, server_public) = keypair();
        let mut client = create_client(&client_private, &server_public)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        let mut server = create_server(&server_private, &client_public)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        let mut first = [0_u8; MAXIMUM_HANDSHAKE_SIZE];
        let first_len =
            write_handshake(&mut client, &mut first).unwrap_or_else(|e| std::panic::panic_any(e));
        read_handshake(&mut server, &first[..first_len])
            .unwrap_or_else(|e| std::panic::panic_any(e));
        let mut second = [0_u8; MAXIMUM_HANDSHAKE_SIZE];
        let second_len =
            write_handshake(&mut server, &mut second).unwrap_or_else(|e| std::panic::panic_any(e));
        read_handshake(&mut client, &second[..second_len])
            .unwrap_or_else(|e| std::panic::panic_any(e));
        (client, server)
    }

    #[test]
    fn successful_ik_handshake_and_transport() {
        let (mut client, mut server) = established();
        assert!(matches!(client.state, SessionState::Transport(_)));
        assert!(matches!(server.state, SessionState::Transport(_)));
        let mut cipher = [0_u8; 64];
        let n = encrypt(&mut client, 0, b"ping", &mut cipher)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        let mut plain = [0_u8; 64];
        let p = decrypt(&mut server, 0, &[], &cipher[..n], &mut plain)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        assert_eq!(&plain[..p], b"ping");
        let n = encrypt(&mut server, 0, b"pong", &mut cipher)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        let p = decrypt(&mut client, 0, &[], &cipher[..n], &mut plain)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        assert_eq!(&plain[..p], b"pong");
    }

    #[test]
    fn tamper_and_replay_are_rejected() {
        let (mut client, mut server) = established();
        let mut cipher = [0_u8; 64];
        let n = encrypt(&mut client, 0, b"ping", &mut cipher)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        cipher[0] ^= 1;
        assert_eq!(
            decrypt(&mut server, 0, &[], &cipher[..n], &mut [0_u8; 64]),
            Err(ErrorCode::AuthenticationFailed)
        );
        cipher[0] ^= 1;
        assert!(decrypt(&mut server, 0, &[], &cipher[..n], &mut [0_u8; 64]).is_ok());
        assert_eq!(
            decrypt(&mut server, 0, &[], &cipher[..n], &mut [0_u8; 64]),
            Err(ErrorCode::ReplayDetected)
        );
    }

    #[test]
    fn wrong_static_and_wrong_order_fail() {
        let (client_private, _) = keypair();
        let (server_private, server_public) = keypair();
        let (_, wrong_public) = keypair();
        let mut client = create_client(&client_private, &server_public)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        let mut server = create_server(&server_private, &wrong_public)
            .unwrap_or_else(|e| std::panic::panic_any(e));
        assert_eq!(
            read_handshake(&mut client, b"invalid"),
            Err(ErrorCode::InvalidState)
        );
        let mut first = [0_u8; MAXIMUM_HANDSHAKE_SIZE];
        let n =
            write_handshake(&mut client, &mut first).unwrap_or_else(|e| std::panic::panic_any(e));
        assert_eq!(
            read_handshake(&mut server, &first[..n]),
            Err(ErrorCode::AuthenticationFailed)
        );
    }

    #[test]
    fn replay_window_allows_reordering_and_rejects_stale() {
        let mut window = ReplayWindow::new();
        window.mark(2048);
        assert!(window.check(2047).is_ok());
        window.mark(2047);
        assert_eq!(window.check(2047), Err(ErrorCode::ReplayDetected));
        assert_eq!(window.check(0), Err(ErrorCode::ReplayDetected));
    }

    #[test]
    fn abi_validation_destroy_and_panic_boundary() {
        assert_eq!(
            // SAFETY: This deliberately passes invalid pointers to verify ABI validation without dereference.
            unsafe {
                halo_session_create_client(
                    std::ptr::null(),
                    32,
                    std::ptr::null(),
                    32,
                    std::ptr::null_mut(),
                )
            },
            ErrorCode::InvalidArgument as u32
        );
        let (client_private, _) = keypair();
        let (_, server_public) = keypair();
        let mut handle = 0;
        assert_eq!(
            // SAFETY: Both key buffers and the handle output remain valid for the call.
            unsafe {
                halo_session_create_client(
                    client_private.as_ptr(),
                    32,
                    server_public.as_ptr(),
                    32,
                    &raw mut handle,
                )
            },
            0
        );
        let mut required = 0_usize;
        assert_eq!(
            // SAFETY: Null with zero capacity is intentional and output-length points to valid storage.
            unsafe {
                halo_session_write_handshake(handle, std::ptr::null_mut(), 0, &raw mut required)
            },
            ErrorCode::BufferTooSmall as u32
        );
        assert_eq!(halo_session_destroy(handle), 0);
        assert_eq!(
            halo_session_destroy(handle),
            ErrorCode::InvalidHandle as u32
        );
        assert_eq!(
            ffi_boundary(|| -> Result<(), ErrorCode> { panic!("test panic") }),
            ErrorCode::InternalError as u32
        );
    }
}
