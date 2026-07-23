# Adding a signing algorithm

Extends the cryptography layer.
Read the Cryptography section of [`ARCHITECTURE.md`](ARCHITECTURE.md) first.

## The contract

Implement one or both interfaces in `src/Cryptography/`:

```php
interface Signer
{
    public function name(): string;   // JWS "alg" value, e.g. "ES384"
    public function kid(): ?string;   // delegate to $key->getId()
    public function sign(string $message): string;  // returns RAW signature bytes
}

interface Verifier
{
    public function verify(string $plain, string $signature): void;  // RAW bytes; throw on mismatch
    public function kid(): ?string;
}
```

`sign()` returns raw bytes (the `Generator` base64url-encodes them).
`verify()` receives raw bytes and throws `InvalidSignatureException` — it never returns a bool.
Symmetric algorithms use one class for both interfaces; asymmetric ones split into `*Signer` / `*Verifier`.
Give the verifier a `name()` method too (all built-ins have one): the `Parser` rejects tokens whose header `alg`
contradicts it.

## Steps

1. **Keys** (`src/Cryptography/Keys/`), if a new key type is needed: mirror `HmacKey` (raw string) or
   `RsaPrivateKey`/`RsaPublicKey` (OpenSSL, path-or-inline-PEM).
   Accept `?string $id = null` last, for `kid`.
2. **Algorithm classes** (`src/Cryptography/Algorithms/<Family>/`): share logic via an `Abstract*` base and/or
   `Algorithm` trait as RSA/ECDSA do; variants set only `protected static string $name`.
   Wrap failures in `SigningException` / `InvalidSignatureException`.
3. **Signature format**: convert on the boundary if your backend's encoding isn't the JWS form — see
   `AbstractEcdsaSigner::derToSignature` / `AbstractEcdsaVerifier::signatureToDer` (DER↔raw).
4. **Optional extensions**: guard with `function_exists()` and add to `suggest` in `composer.json` (as EdDSA
   does for `ext-sodium`).
5. **Tests** under `tests/Cryptography/...` following [`TESTING.md`](TESTING.md); test keys go in `assets/keys/`.
6. **Docs**: add to the README's algorithm list with an example and a round-trip in `tests/ExamplesTest.php`.

## Constraints

- PHP 7.4-compatible, `declare(strict_types=1);`, no new runtime dependencies.
- Match the RFC 7518 `alg` id and its specified hash exactly; interoperability depends on it.
- Prefer `hash_equals` for symmetric MAC verification.
