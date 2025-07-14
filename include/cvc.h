//
// Created by Peter Paravinja on 11. 7. 25.
//

#ifndef CVC_H
#define CVC_H

#ifdef __cplusplus
extern "C" {
#endif

    // ============================================================================
    // Include external library headers to expose their functions
    // ============================================================================

    // MIRACL Core includes - expose elliptic curve cryptography
#include "core.h"          // Main MIRACL core functions
#include "ecdh_Ed25519.h"   // Curve25519 ECDH
#include "ecdh_NIST256.h"   // Curve25519 ECDH
#include "ecp_Ed25519.h"   // NIST P-256 curve
#include "ecp_NIST256.h"       // NIST P-256 curve
#include "eddsa_Ed25519.h"     // NIST P-256 curve
#include "eddsa_NIST256.h"   // NIST P-256 curve

    // l8w8jwt includes - expose JWT functionality
#include "l8w8jwt/encode.h"  // JWT encoding
#include "l8w8jwt/decode.h"  // JWT decoding
#include "l8w8jwt/algs.h"    // Algorithm definitions

#ifdef __cplusplus
}
#endif

#endif // CVC_H