//
// Created by Peter Paravinja on 10. 7. 25.
//

#ifndef CRYPTO_H
#define CRYPTO_H

// Include the main CVC header which exposes all library functions
#include "cvc.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Returns a simple hello world string for testing purposes
     * @return "Hello World from CVC Library"
     */
    const char* cvc_hello_world(void);

#ifdef __cplusplus
}
#endif

#endif //CRYPTO_H