# cvc-go

> Go SDK for Cryptographic Verifiable Credentials (CVC). Wraps a native C library to provide NIST P-256 elliptic curve
> cryptographic operations — key generation, scalar and point addition, and hash-to-field key derivation — used to issue
> and deliver verifiable credentials in a secure two-party key split architecture.

**Status:** 🟢 Active
**Stack:** `Go` `CGo` `NIST P-256` `JWK` `MessagePack`  
**Owner:** @peter.paravinja — *(the go-to person for questions)*  

---

## Local setup

### Prerequisites

- Go >= 1.24.2
- GCC or Clang (CGo is required — the SDK wraps a precompiled C library)
- Supported platforms: `darwin/arm64`, `linux/amd64`, `linux/arm64`, `windows/amd64`
- Precompiled C library binaries under `lib/` and headers under `include/` must be present (not committed to this repo —
  obtain from the team)

### Clone & run

```bash
git clone git@github.com:MyNextID/cvc-go.git
cd cvc-go
go mod download
```

### Verify it works

```bash
go test ./... -run TestGenerateSecretKey -v
```

A passing test confirms CGo bindings, the C library, and Go toolchain are all wired up correctly.

---

## Project structure

```
├── cvc.go                  # Public API — GenerateSecretKey, AddSecretKeys, AddPublicKeys, DeriveSecretKey
├── issuer.go               # IssuerConfig — F0/F1/F2 credential issuance workflow
├── provider.go             # ProviderConfig — wallet provider key generation and derivation
├── types.go                # Shared types — UserData, MessagePack, KeyData, etc.
├── internal/
│   ├── cbindings.go        # CGo layer — calls into the C library, handles memory layout
│   └── errors.go           # Error definitions and C error code mapping
├── pkg/
│   ├── ecdsa.go            # ECDSA public key marshal/unmarshal helpers
│   └── utils.go            # JWK/JSON helpers, JWE encrypt/decrypt, UUID, SHA-256
├── builder/
│   ├── presentation.go     # Presentation builder — generates credential display JSON
│   ├── elements.go         # Element definition and validation
│   ├── groups.go           # Group definition and validation
│   ├── languages.go        # ISO 639-1 language validation
│   └── formats.go          # Element format types (date-time, duration)
├── examples/
│   └── presentations/      # Example presentation JSON configs (COA, microcredential)
├── include/                # C library header files (CGo uses these)
└── lib/                    # Precompiled C library binaries per platform
```

---

## Development

### Running tests

```bash
# All tests
go test ./...

# Verbose output
go test ./... -v

# Specific package
go test ./builder/... -v

# Specific test
go test -run TestAddSecretKeys/ArithmeticVerification -v
```

> **Note:** Tests in the root package (`package cvc`) require the C library to be present under `lib/`. Tests in
`builder/` are pure Go and run without it.

### Linting & formatting

```bash
golangci-lint run
gofmt -w .
```

### Building

This is a library — there is no binary to build. Consumers import it as a Go module:

```go
import "github.com/MyNextID/cvc-go"
```

### Cross-compilation

CGo does not support standard Go cross-compilation. To build for a different target platform you need the C library
binary for that platform under `lib/<os>/<arch>/` and a matching C cross-compiler. Match the directory names used in
`internal/cbindings.go`:

| OS      | Arch   | Library path          |
|---------|--------|-----------------------|
| macOS   | ARM64  | `lib/darwin/arm64/`   |
| Linux   | x86-64 | `lib/linux/x86_64/`   |
| Linux   | ARM64  | `lib/linux/aarch64/`  |
| Windows | x86-64 | `lib/windows/x86_64/` |

---

## Architecture overview

The SDK implements a **three-party verifiable credential** system:

| Role                | Type             | Responsibility                                                                                                             |
|---------------------|------------------|----------------------------------------------------------------------------------------------------------------------------|
| **Issuer**          | `IssuerConfig`   | Generates credentials, interacts with the wallet provider to build confirmation keys, packages the credential for delivery |
| **Wallet Provider** | `ProviderConfig` | Holds a master secret key, derives user-specific key shares on demand                                                      |
| **User**            | —                | Receives a MessagePack via email, contacts the wallet provider to decrypt their credential                                 |

### Key issuance flow

```
F0  Issuer  →  Wallet Provider   Request public key shares for a set of user email hashes
F1  Issuer                       Generate VC key pair, combine VC public key + WP public key into cnf key, embed in VC payload
F2  Issuer                       Sign credential, encrypt with VC public key, encrypt VC secret key with WP public key, pack into MessagePack → send via email
```

The VC secret key is **never transmitted unencrypted**. Decryption requires both the issuer-generated VC secret key (
encrypted under the WP public key) and the wallet provider's derived secret key — neither party can decrypt the
credential alone.

### Core cryptographic operations

All operations use NIST P-256. The Go layer handles input validation and memory management; the C library performs the
actual curve arithmetic.

| Function                                | Description                                                                    |
|-----------------------------------------|--------------------------------------------------------------------------------|
| `GenerateSecretKey()`                   | Generate a cryptographically random P-256 private key                          |
| `AddSecretKeys(k1, k2)`                 | Scalar addition mod curve order: `(d1 + d2) mod n`                             |
| `AddPublicKeys(k1, k2)`                 | Elliptic curve point addition: `P1 + P2`                                       |
| `DeriveSecretKey(master, context, dst)` | Hash-to-field derivation — deterministic child key from master + context + DST |

All functions accept and return `jwk.Key` (from `github.com/lestrrat-go/jwx/v2/jwk`). Errors are always returned, never
panicked.

---

## Troubleshooting

| Problem                                                | Fix                                                                                                                |
|--------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `cannot find -lcvc` at build time                      | C library binaries are missing. Check `lib/<os>/<arch>/` matches your platform and `include/` has the headers      |
| `cgo: C compiler not found`                            | Install GCC: `apt install build-essential` (Linux) or Xcode command line tools (macOS)                             |
| Tests pass in `builder/` but fail in root package      | Root package tests require the C library. Confirm `lib/` is populated                                              |
| `go test ./...` hangs                                  | A test may be waiting on network (issuer tests hit `ProviderURL`). Run `go test ./... -timeout 30s`                |
| Key derivation returns different results than expected | Check that `context` and `dst` byte slices are identical — derivation is fully deterministic given the same inputs |

---

## Related resources

- **C library source:** [link](https://github.com/MyNextID/cvc)