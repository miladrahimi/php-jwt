# Architecture

Maintainer reference for how `miladrahimi/php-jwt` is built.
Summary: [`../CLAUDE.md`](../CLAUDE.md).

## The shape of a JWT

```
base64url(header) . base64url(payload) . base64url(signature)
      │                     │                     │
      │                     │                     └─ signature over "header.payload"
      │                     └─ claims (JSON object)
      └─ {"typ":"JWT","alg":"<algorithm>"[,"kid":"<key id>"]}
```

The header `alg` is metadata only — **the parser never uses it to pick an algorithm automatically**.
This blocks the "alg confusion" downgrade attack (`RS256`→`HS256`/`none`).

## Design principles

- **Small interfaces, constructor injection** — every concern is swappable without subclassing.
- **No runtime dependencies** — PHP + `ext-openssl` + `ext-json` (+ `ext-sodium` for EdDSA).
- **PHP 7.4 floor** — typed properties yes; enums/`match`/promotion no.
- **Typed exceptions** — every failure is a `JwtException` subclass, so callers catch the base type broadly or
  a specific subclass narrowly.

## Component map

```
Generator ──> Signer, JsonParser, Base64Parser
Parser    ──> Verifier, Validator, JsonParser, Base64Parser
VerifierFactory ──maps kid──> Verifier[]
```

| Concern     | Interface                | Default                      |
|-------------|--------------------------|------------------------------|
| Signing     | `Cryptography/Signer`    | per-algorithm                |
| Verifying   | `Cryptography/Verifier`  | per-algorithm                |
| Claim rules | `Validator/Validator`    | `Validator/DefaultValidator` |
| JSON        | `Json/JsonParser`        | `Json/StrictJsonParser`      |
| Base64url   | `Base64/Base64Parser`    | `Base64/SafeBase64Parser`    |

## Flows

**Generate** (`Generator::generate`): build header (`typ`, `alg`, `kid` if the key has an id) →
base64url(json) each of header and claims → sign `header.payload` → join with `.`.
Throws `JsonEncodingException` / `SigningException`.

**Parse** (`Parser::parse`): split into 3 (`InvalidTokenException`) → validate header (`typ` must be `"JWT"`;
`kid`, if present, must match the verifier) → verify signature (`InvalidSignatureException`) → decode payload
→ validate claims (`ValidationException`) → return claims.
The signature is verified **before** the payload is decoded — keep that order.
`Parser` also exposes `verify()` (signature only) and `validate()` (signature + claims).

## Cryptography (`src/Cryptography/`)

`Signer` = `name()` + `kid()` + `sign()`; `Verifier` = `verify()` + `kid()`.
`kid()` delegates to the key's `getId()`.

- **HMAC** (`Algorithms/Hmac/`) — `AbstractHmac` is both `Signer` and `Verifier`; `HS256/384/512` set only
  `$name`.
  Enforces key length `[32, 6144]`, uses `hash_hmac(..., raw=true)`.
  `verify()` compares with `!==` (not constant-time — see quirks).
- **RSA** (`Algorithms/Rsa/`) — split `AbstractRsaSigner`/`AbstractRsaVerifier` (both `use Algorithm` trait
  mapping name → `OPENSSL_ALGO_SHA*`).
  Uses `openssl_sign`/`openssl_verify`; output is already JWS form.
- **ECDSA** (`Algorithms/Ecdsa/`) — the subtle part.
  OpenSSL speaks **DER** (`SEQUENCE(INTEGER r, INTEGER s)`) but JWS needs raw `R || S`.
  `sign()` converts DER→raw (`derToSignature`, left-pad each half to `keySize/8`: 32 bytes for ES256/ES256K,
  48 for ES384); `verify()` converts raw→DER (`signatureToDer`) before `openssl_verify`.
  `algorithm()` maps ES256/ES256K → SHA-256, **ES384 → SHA-512** (see quirks).
  The DER codec handles only ECDSA signatures — don't generalize it.
- **EdDSA** (`Algorithms/Eddsa/`) — standalone signer/verifier via `sodium_crypto_sign_detached` /
  `..._verify_detached`, guarded by `function_exists()`.
  Keys are raw Ed25519 bytes (README base64-decodes them).

### Keys (`Cryptography/Keys/`)

- **String-content** — `HmacKey`, `EdDsaPrivateKey`, `EdDsaPublicKey`: `__construct(string $key, ?string $id)`,
  `getContent()`, no file I/O.
- **OpenSSL** — `Rsa*`, `Ecdsa*`: `getResource()` (`OpenSSLAsymmetricKey`/resource, typed `mixed`).
  All four load identically — `realpath($key) ? file_get_contents(...) : $key` — so a **file path or inline
  PEM** both work.
  Private keys add a passphrase (`(string $key, string $passphrase = '', ?string $id)`,
  `openssl_pkey_get_private`); public keys `(string $key, ?string $id)`, `openssl_pkey_get_public`.
  Failures throw `InvalidKeyException`.
  RSA and ECDSA key classes are identical; the curve comes from the key material.

### `VerifierFactory`

Indexes verifiers by `kid()`.
`getVerifier($jwt)` reads the token's `kid` and returns the match, else `NoKidException` /
`VerifierNotFoundException`.
Non-`Verifier` elements throw `InvalidArgumentException`.

## Validation (`src/Validator/`)

`Validator::validate(array $claims)`; `Rule::validate(string $name, $value)` throws `ValidationException`.

- **`BaseValidator`** stores `$rules[$claim][] = [$rule, $required]`.
  When a claim is present, every rule runs; when absent, a **required** rule throws and an **optional** one is
  skipped.
  "Required" governs presence only.
- **`DefaultValidator`** pre-registers optional, time-based rules (using `time()` at construction):
  `exp → NewerThan`, `nbf → OlderThanOrSame`, `iat → OlderThanOrSame`.
  Build a fresh instance per request.

Built-in rules (`Validator/Rules/`):

| Rule                                        | Fails when                        |
|---------------------------------------------|-----------------------------------|
| `GreaterThan` / `GreaterThanOrEqualTo`      | `value <= number` / `< number`    |
| `LessThan` / `LessThanOrEqualTo`            | `value >= number` / `> number`    |
| `NewerThan` / `NewerThanOrSame`             | aliases of the two `Greater*`     |
| `OlderThan` / `OlderThanOrSame`             | aliases of the two `Less*`        |
| `EqualsTo` / `IdenticalTo`                  | `!=` (loose) / `!==` (strict)     |
| `ConsistsOf`                                | value doesn't contain substring   |
| `NotEmpty` / `NotNull`                      | `empty($value)` / `=== null`      |

Custom rules implement `Rule` and throw `ValidationException`.

## Encoding helpers

- **`SafeBase64Parser`** — URL-safe base64 (`+/`↔`-_`, strips/re-pads `=`).
  Never throws.
- **`StrictJsonParser`** — wraps `json_encode`/`json_decode` (associative), checks `json_last_error()`, throws
  `JsonEncodingException` / `JsonDecodingException`; also rejects non-array JSON.

## Exceptions

Two levels: `JwtException extends \Exception`, and every concrete exception extends `JwtException` directly —
`InvalidKeyException`, `InvalidSignatureException`, `InvalidTokenException`, `JsonDecodingException`,
`JsonEncodingException`, `NoKidException`, `SigningException`, `ValidationException`, `VerifierNotFoundException`.
Catch `JwtException` for all, or a subclass for specifics.

## Known quirks

Documented so they aren't mistaken for bugs — confirm intent before changing.

1. **`ES384` uses SHA-512**, not SHA-384 (`Ecdsa/Algorithm.php`).
   RFC 7518 says SHA-384.
   Self-consistent here but may not interoperate; changing it breaks all previously issued ES384 tokens.
2. **HMAC verify is not constant-time** — `!==` instead of `hash_equals()`.
3. **README typos** — lists `RS384` under ECDSA where `ES384` is meant.
4. **Minor:** `AbstractRsaSigner` param named `$publicKey` (holds the private key); some files miss
   `declare(strict_types=1)`; `EdDsaVerifier` message is garbled; `BaseValidator::addOptionalRule` has a
   copy-pasted docblock.

Good candidates for the next cycle — all low-risk except (1), which needs a compatibility decision.
