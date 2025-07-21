//
// Created by Peter Paravinja on 21. 7. 25.
//
#ifndef ECP_OPERATIONS_H
#define ECP_OPERATIONS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result codes for ECP operations
 */
typedef enum
{
    CVC_ECP_SUCCESS = 0,                         /**< Operation completed successfully */
    CVC_ECP_ERROR_INVALID_KEY1_LENGTH = -1,      /**< First key has invalid length */
    CVC_ECP_ERROR_INVALID_KEY2_LENGTH = -2,      /**< Second key has invalid length */
    CVC_ECP_ERROR_INVALID_POINT_1 = -3,          /**< First key bytes do not represent a valid ECP point */
    CVC_ECP_ERROR_INVALID_POINT_2 = -4,          /**< Second key bytes do not represent a valid ECP point */
    CVC_ECP_ERROR_POINT_1_AT_INFINITY = -5,      /**< First point is at infinity (invalid) */
    CVC_ECP_ERROR_POINT_2_AT_INFINITY = -6,      /**< Second point is at infinity (invalid) */
    CVC_ECP_ERROR_RESULT_AT_INFINITY = -7,       /**< Result point is at infinity (invalid) */
    CVC_ECP_ERROR_RESULT_CONVERSION_FAILED = -8, /**< Failed to convert result point to bytes */
    CVC_ECP_ERROR_INSUFFICIENT_BUFFER = -9       /**< Result buffer is too small */
} cvc_ecp_result_t;

/**
 * @brief Add two NIST P-256 public keys (elliptic curve point addition)
 *
 * This function performs elliptic curve point addition on the NIST P-256 curve.
 * Both input keys must be in uncompressed format (65 bytes: 0x04 || X || Y).
 * The result will also be in uncompressed format.
 *
 * @param key1_bytes First public key in uncompressed format (65 bytes)
 * @param key1_len Length of first key bytes (must be 65)
 * @param key2_bytes Second public key in uncompressed format (65 bytes)
 * @param key2_len Length of second key bytes (must be 65)
 * @param result_bytes Output buffer for the result (must be at least 65 bytes)
 * @param result_buffer_size Size of the result buffer
 * @param actual_result_len Pointer to store the actual length of the result (will be 65)
 * @return CVC_ECP_SUCCESS on success, or a negative error code on failure
 */
int cvc_add_nist256_public_keys(const unsigned char* key1_bytes, int key1_len, const unsigned char* key2_bytes, int key2_len, unsigned char* result_bytes, int result_buffer_size, int* actual_result_len);

#ifdef __cplusplus
}
#endif

#endif // ECP_OPERATIONS_H