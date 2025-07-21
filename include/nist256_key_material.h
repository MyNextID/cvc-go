//
// Created by Peter Paravinja on 17. 7. 25.
//

#ifndef NIST256_KEY_MATERIAL_H
#define NIST256_KEY_MATERIAL_H

#include "big_256_56.h"
#include "ecp_NIST256.h"
#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif

// Structure to hold the extracted key material
typedef struct
{
    unsigned char private_key_bytes[MODBYTES_256_56];
    unsigned char public_key_x_bytes[MODBYTES_256_56];
    unsigned char public_key_y_bytes[MODBYTES_256_56];
} nist256_key_material_t;

/**
 * @brief Generate a cryptographically secure random private key for NIST P-256
 *
 * This function creates a MIRACL CSPRNG, seeds it with the provided random bytes,
 * and generates a random private key scalar in the valid range [1, curve_order-1].
 *
 * @param secret_key Output parameter to store the generated private key
 * @param random_seed Array of random bytes for seeding the RNG
 * @param seed_len Length of the random seed array (recommended: 32 bytes)
 * @return 0 on success, non-zero on error
 */
int nist256_generate_secret_key(BIG_256_56 secret_key, unsigned char* random_seed, int seed_len);

/**
 * @brief Extract key material from MIRACL BIG private key scalar
 *
 * This function takes a MIRACL BIG number representing a private key scalar,
 * computes the corresponding public key point on the NIST P-256 curve,
 * and extracts the raw bytes for private key and public key coordinates.
 *
 * @param d BIG_256_56 private key scalar
 * @param key_material Pointer to structure to hold the extracted key material
 * @return 0 on success, non-zero on error
 */
int nist256_big_to_key_material(BIG_256_56 d, nist256_key_material_t* key_material);

#ifdef __cplusplus
}
#endif

#endif // NIST256_KEY_MATERIAL_H