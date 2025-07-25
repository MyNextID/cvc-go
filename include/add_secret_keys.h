//
// Created by Peter Paravinja on 25. 7. 25.
//
#ifndef ADD_SECRET_KEYS_H
#define ADD_SECRET_KEYS_H

#include "nist256_key_material.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result codes for secret key addition operations
 */
typedef enum
{
    CVC_ADD_SECRET_KEYS_SUCCESS = 0,                      /**< Operation completed successfully */
    CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS = -1,        /**< Invalid input parameters */
    CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY1 = -2,          /**< First key is invalid (zero or >= curve order) */
    CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY2 = -3,          /**< Second key is invalid (zero or >= curve order) */
    CVC_ADD_SECRET_KEYS_ERROR_RESULT_ZERO = -4,           /**< Result scalar is zero (invalid private key) */
    CVC_ADD_SECRET_KEYS_ERROR_KEY_EXTRACTION_FAILED = -5, /**< Failed to extract complete key material */
} cvc_add_secret_keys_result_t;

/**
 * @brief Add two NIST P-256 private key scalars modulo curve order
 *
 * This function performs scalar addition (d1 + d2) mod n where n is the NIST P-256
 * curve order. Both input private keys must be valid scalars in the range [1, n-1].
 * The result will also be in the valid range [1, n-1].
 *
 * The operation performed is:
 * 1. Validate that both input keys are in valid range [1, curve_order-1]
 * 2. Compute sum = (key1 + key2) mod curve_order using MIRACL arithmetic
 * 3. Ensure result is not zero (which would be invalid)
 * 4. Generate complete key material including public key coordinates
 *
 * @param key1_bytes First private key as 32-byte big-endian scalar
 * @param key1_len Length of first key bytes (must be 32)
 * @param key2_bytes Second private key as 32-byte big-endian scalar
 * @param key2_len Length of second key bytes (must be 32)
 * @param result_key_material Output structure to store the complete derived key material
 * @return CVC_ADD_SECRET_KEYS_SUCCESS on success, or a negative error code on failure
 */
int cvc_add_nist256_secret_keys(const unsigned char* key1_bytes, int key1_len, const unsigned char* key2_bytes, int key2_len, nist256_key_material_t* result_key_material);

#ifdef __cplusplus
}
#endif

#endif // ADD_SECRET_KEYS_H
