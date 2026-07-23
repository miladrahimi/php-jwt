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

The header `alg` never picks an algorithm — **the configured verifier's algorithm is always the one used**.
This blocks the "alg confusion" downgrade attack (`RS256`→`HS256`/`none`).
As defense in depth, a present `alg` that contradicts the verifier's `name()` is rejected
(`InvalidTokenException`); this applies to `NamedVerifier` implementations (all built-ins are).

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
`alg` and `kid`, if present, must match the verifier) → verify signature (`InvalidSignatureException`) →
decode payload → validate claims (`ValidationException`) → return claims.
The signature is verified **before** the payload is decoded — keep that order.
`Parser` also exposes `verify()` (header + signature) and `validate()` (header + signature + claims);
all three entry points run the same header validation.

## Cryptography (`src/Cryptography/`)

`Signer` = `name()` + `kid()` + `sign()`; `Verifier` = `verify()` + `kid()`; `NamedVerifier` extends `Verifier`
with `name()` (all built-in verifiers implement it).
`kid()` delegates to the key's `getId()`.

- **HMAC** (`Algorithms/Hmac/`) — `AbstractHmac` is both `Signer` and `Verifier`; `HS256/384/512` set only
  `$name`.
  Enforces key length `[32, 6144]`, uses `hash_hmac(..., raw=true)`.
  `verify()` compares with constant-time `hash_equals()`.
- **RSA** (`Algorithms/Rsa/`) — split `AbstractRsaSigner`/`AbstractRsaVerifier` (both `use Algorithm` trait
  mapping name → `OPENSSL_ALGO_SHA*`).
  Uses `openssl_sign`/`openssl_verify`; output is already JWS form.
- **ECDSA** (`Algorithms/Ecdsa/`) — the subtle part.
  OpenSSL speaks **DER** (`SEQUENCE(INTEGER r, INTEGER s)`) but JWS needs raw `R || S`.
  `sign()` converts DER→raw (`derToSignature`, left-pad each half to `coordinateSize()`: 32 bytes for
  ES256/ES256K, 48 for ES384, and 66 for ES512 — P-521's 521 bits round up to whole bytes); `verify()` rejects
  raw signatures whose length doesn't match the curve, then converts raw→DER (`signatureToDer`) before
  `openssl_verify`. ES512 SEQUENCEs exceed 127 content bytes, so `encodeDer` emits the one-byte long-form
  length (`0x81` prefix) above that.
  `algorithm()` maps ES256/ES256K → SHA-256, ES384 → SHA-384, ES512 → SHA-512 (per RFC 7518 §3.1).
  The DER codec handles only ECDSA signatures — don't generalize it.
- **EdDSA** (`Algorithms/Eddsa/`) — standalone signer/verifier via `sodium_crypto_sign_detached` /
  `..._verify_detached`, guarded by `function_exists()`.
  Keys are raw Ed25519 bytes (README base64-decodes them).

### Keys (`Cryptography/Keys/`)

- **String-content** — `HmacKey`, `EdDsaPrivateKey`, `EdDsaPublicKey`: `__construct(string $key, ?string $id)`,
  `getContent()`, no file I/O.
- **OpenSSL** — `Rsa*`, `Ecdsa*`: `getResource()` (`OpenSSLAsymmetricKey`/resource, typed `mixed`).
  All four load identically — `is_file($key) ? file_get_contents(...) : $key` — so a **file path or inline
  PEM** both work.
  Private keys add a passphrase (`(string $key, string $passphrase = '', ?string $id)`,
  `openssl_pkey_get_private`); public keys `(string $key, ?string $id)`, `openssl_pkey_get_public`.
  Failures throw `InvalidKeyException`.
  RSA and ECDSA key classes are identical; the curve comes from the key material.

### `VerifierFactory`

Indexes verifiers by `kid()`.
`getVerifier($jwt)` reads the token's `kid` and returns the match, else `NoKidException` /
`VerifierNotFoundException`; a non-string `kid` throws `InvalidTokenException`.
Non-`Verifier` elements throw `InvalidArgumentException`.
A verifier without a `kid` registers under `""` and is matched only by a token whose header has `"kid": ""`
(kept for backward compatibility).

## Validation (`src/Validator/`)

`Validator::validate(array $claims)`; `Rule::validate(string $name, $value)` throws `ValidationException`.

- **`BaseValidator`** stores `$rules[$claim][] = [$rule, $required]`.
  When a claim is present, every rule runs; when absent, a **required** rule throws and an **optional** one is
  skipped.
  "Required" governs presence only.
- **`DefaultValidator`** applies optional, time-based rules on every `validate()` call (using the current
  `time()`, so long-lived instances stay correct):
  `exp → NewerThan`, `nbf → OlderThanOrSame`, `iat → OlderThanOrSame`.

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
  Decoding is strict: input outside the base64 alphabet throws `InvalidTokenException`.
- **`StrictJsonParser`** — wraps `json_encode`/`json_decode` (associative), checks `json_last_error()`, throws
  `JsonEncodingException` / `JsonDecodingException`; also rejects non-array JSON.

## Exceptions

Two levels: `JwtException extends \Exception`, and every concrete exception extends `JwtException` directly —
`InvalidKeyException`, `InvalidSignatureException`, `InvalidTokenException`, `JsonDecodingException`,
`JsonEncodingException`, `NoKidException`, `SigningException`, `ValidationException`, `VerifierNotFoundException`.
Catch `JwtException` for all, or a subclass for specifics.

## Known quirks

Intentional oddities, documented so they aren't mistaken for bugs — confirm intent before changing.

None at the moment.
