//
// Created by Peter Paravinja on 21. 7. 25.
//

#ifndef HASH_TO_FIELD_H
#define HASH_TO_FIELD_H

#include "fp_NIST256.h"
#include "nist256_key_material.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result codes for hash-to-field operations
 */
typedef enum
{
    CVC_HASH_TO_FIELD_SUCCESS = 0,                    /**< Operation completed successfully */
    CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS = -1,      /**< Invalid input parameters */
    CVC_HASH_TO_FIELD_ERROR_EXPAND_FAILED = -2,       /**< XMD expansion failed */
    CVC_HASH_TO_FIELD_ERROR_EXPANSION_TOO_LARGE = -3, /**< Expansion length exceeds buffer limits */
} cvc_hash_to_field_result_t;

/**
 * @brief Result codes for secret key derivation operations
 */
typedef enum
{
    CVC_DERIVE_KEY_SUCCESS = 0,                      /**< Operation completed successfully */
    CVC_DERIVE_KEY_ERROR_INVALID_PARAMS = -1,        /**< Invalid input parameters */
    CVC_DERIVE_KEY_ERROR_INPUT_TOO_LARGE = -2,       /**< Combined input exceeds buffer limits */
    CVC_DERIVE_KEY_ERROR_HASH_TO_FIELD_FAILED = -3,  /**< Hash-to-field operation failed */
    CVC_DERIVE_KEY_ERROR_ZERO_SCALAR = -4,           /**< Resulted in zero scalar (invalid key) */
    CVC_DERIVE_KEY_ERROR_KEY_EXTRACTION_FAILED = -5, /**< Key material extraction failed */
} cvc_derive_key_result_t;

/**
 * @brief Hash arbitrary data to field elements using RFC 9380 hash-to-field specification
 *
 * This function implements the hash_to_field operation as specified in RFC 9380
 * for the NIST P-256 curve. It uses XMD (eXpand Message Direct) with the specified
 * hash function to produce uniformly distributed field elements.
 *
 * @param hash Hash function family (e.g., MC_SHA2)
 * @param hash_len Hash function output length (e.g., HASH_TYPE_NIST256 for SHA-256)
 * @param dst Domain Separation Tag as byte array
 * @param dst_len Length of the DST
 * @param message Input message to be hashed
 * @param message_len Length of the input message
 * @param count Number of field elements to generate (must be > 0)
 * @param field_elements Output array to store the generated field elements (must be pre-allocated)
 * @return CVC_HASH_TO_FIELD_SUCCESS on success, or a negative error code on failure
 */
int cvc_hash_to_field_nist256(const int hash, const int hash_len, const unsigned char* dst, const int dst_len, const unsigned char* message, const int message_len, const int count, FP_NIST256* field_elements);

/**
 * @brief Derive a secret key from master key material using hash-to-field
 *
 * This function derives a NIST P-256 private key from master key material and context
 * using the hash-to-field operation. The derived key is guaranteed to be in the valid
 * range [1, curve_order-1] and suitable for cryptographic operations.
 *
 * The derivation process:
 * 1. Combines master_key_bytes and context into a single input
 * 2. Uses hash-to-field to generate a field element
 * 3. Reduces the result modulo the curve order to get a valid scalar
 * 4. Extracts complete key material including public key coordinates
 *
 * @param master_key_bytes Master key material as byte array
 * @param master_key_len Length of the master key material
 * @param context Context bytes for key derivation (for domain separation)
 * @param context_len Length of the context
 * @param dst Domain Separation Tag as byte array
 * @param dst_len Length of the DST
 * @param derived_key_material Output structure to store the derived key material
 * @return CVC_DERIVE_KEY_SUCCESS on success, or a negative error code on failure
 */
int cvc_derive_secret_key_nist256(const unsigned char* master_key_bytes, int master_key_len, const unsigned char* context, int context_len, const unsigned char* dst, int dst_len, nist256_key_material_t* derived_key_material);

#ifdef __cplusplus
}
#endif

#endif // HASH_TO_FIELD_H
