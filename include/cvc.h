//
// Created by Peter Paravinja on 11. 7. 25.
//

#ifndef CVC_UMBRELLA_H
#define CVC_UMBRELLA_H

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Include external library headers to expose their functions
// ============================================================================

// MIRACL Core includes - expose elliptic curve cryptography
#include "core.h"          // Main MIRACL core functions
#include "ecdh_Ed25519.h"  // Curve25519 ECDH
#include "ecdh_NIST256.h"  // Curve25519 ECDH
#include "ecp_Ed25519.h"   // NIST P-256 curve
#include "ecp_NIST256.h"   // NIST P-256 curve
#include "eddsa_Ed25519.h" // NIST P-256 curve
#include "eddsa_NIST256.h" // NIST P-256 curve

// l8w8jwt includes - expose JWT functionality
#include "l8w8jwt/encode.h" // JWT encoding
#include "l8w8jwt/decode.h" // JWT decoding
#include "l8w8jwt/algs.h"   // Algorithm definitions

// CVC library functions
#include "crypto.h"               // Basic CVC functions
#include "nist256_key_material.h" // NIST256 key material extraction
#include "ecp_operations.h"       // Elliptic curve point operations
#include "hash_to_field.h"

#ifdef __cplusplus
}
#endif

#endif // CVC_UMBRELLA_H
