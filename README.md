# CVC-Go

Go SDK for the CVC (Cryptographic Verification Components) library - providing high-performance cryptographic operations
for Go applications.

## Overview

CVC-Go is a Go wrapper around the [CVC C library](https://github.com/MyNextID/cvc), offering:

- **JWT/JOSE Operations**: Complete JWT encoding, decoding, and verification
- **Elliptic Curve Cryptography**: Support for Ed25519, NIST P-256, and other curves
- **Digital Signatures**: EdDSA and ECDSA signature operations
- **Key Management**: Key pair generation and validation
- **Cross-Platform**: Pre-compiled static libraries for all major platforms

Built on battle-tested cryptographic foundations:

- [MIRACL Core](https://github.com/miracl/core) for elliptic curve operations
- [l8w8jwt](https://github.com/GlitchedPolygons/l8w8jwt) for JWT/JOSE functionality

## Installation

```bash
go get github.com/MyNextID/cvc-go
```

No additional setup required! The SDK includes pre-compiled static libraries for:

- **macOS**: arm64, x86_64
- **Linux**: x86_64, aarch64
- **Windows**: x86_64

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/MyNextID/cvc-go"
)

func main() {
    // Test the library integration
    result := cvc.CVCHelloWorld()
    fmt.Printf("CVC Library: %s\n", result)
    
    // Test cryptographic operations
    if cvc.CVCTestMiraclBigAdd() {
        fmt.Println("✅ Cryptographic functions working correctly")
    }
}
```

## Documentation

For detailed information about the underlying cryptographic implementations and algorithms:

- **CVC C Library**: [https://github.com/MyNextID/cvc](https://github.com/MyNextID/cvc)
- **MIRACL Core**: [https://github.com/miracl/core](https://github.com/miracl/core)
- **l8w8jwt**: [https://github.com/GlitchedPolygons/l8w8jwt](https://github.com/GlitchedPolygons/l8w8jwt)

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| macOS    | arm64        | ✅      |
| Linux    | x86_64       | ✅      |
| Linux    | aarch64      | ✅      |
| Windows  | x86_64       | ✅      |

## Requirements

- **Go**: 1.24.2 or later
- **CGO**: Enabled (default)
- **Platform**: One of the supported platforms above

### Releasing

Use the provided release script to create new versions:

```bash
./release.sh v1.0.0
```

## License

MIT License - see [LICENSE](LICENSE) file for details.