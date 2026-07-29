#ifndef HALO_PROTOCOL_H
#define HALO_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define HALO_API __declspec(dllimport)
#else
#define HALO_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t HaloSessionHandle;

typedef enum HaloErrorCode {
    HALO_SUCCESS = 0,
    HALO_INVALID_ARGUMENT = 1,
    HALO_INVALID_STATE = 2,
    HALO_INVALID_PACKET = 3,
    HALO_UNSUPPORTED_VERSION = 4,
    HALO_AUTHENTICATION_FAILED = 5,
    HALO_REPLAY_DETECTED = 6,
    HALO_CAPACITY_EXCEEDED = 7,
    HALO_KEY_LIMIT_REACHED = 8,
    HALO_BUFFER_TOO_SMALL = 9,
    HALO_INVALID_HANDLE = 10,
    HALO_INTERNAL_ERROR = 255
} HaloErrorCode;

HALO_API uint32_t halo_abi_version(void);
HALO_API uint32_t halo_session_create_client(const uint8_t*, size_t, const uint8_t*, size_t, HaloSessionHandle*);
HALO_API uint32_t halo_session_create_server(const uint8_t*, size_t, const uint8_t*, size_t, HaloSessionHandle*);
HALO_API uint32_t halo_session_write_handshake(HaloSessionHandle, uint8_t*, size_t, size_t*);
HALO_API uint32_t halo_session_read_handshake(HaloSessionHandle, const uint8_t*, size_t);
HALO_API uint32_t halo_session_encrypt(HaloSessionHandle, uint64_t, const uint8_t*, size_t, uint8_t*, size_t, size_t*);
HALO_API uint32_t halo_session_decrypt(HaloSessionHandle, uint64_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t, size_t*);
HALO_API uint32_t halo_session_is_established(HaloSessionHandle, uint8_t*);
HALO_API uint32_t halo_session_destroy(HaloSessionHandle);
HALO_API uint32_t halo_generate_keypair(uint8_t*, size_t, uint8_t*, size_t);
HALO_API uint32_t halo_error_message(uint32_t, char*, size_t, size_t*);

#ifdef __cplusplus
}
#endif
#endif
