//
// Created by Peter Paravinja on 10. 7. 25.
//

#ifndef CRYPTO_H
#define CRYPTO_H

#include "cvc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns a simple hello world string for testing purposes
 * @return "Hello World from CVC Library"
 */
const char* cvc_hello_world(void);

/**
 * Simple MIRACL test function - return 1 if success or 0 if failed
 */
int cvc_test_miracl_big_add(void);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_H