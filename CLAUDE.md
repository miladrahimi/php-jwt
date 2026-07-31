# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

`miladrahimi/php-jwt` — a dependency-free PHP library to generate, parse, verify, and validate JWTs.

- **Requirements:** PHP `>=7.4`, `ext-openssl`, `ext-json`; `ext-sodium` only for EdDSA.
- **No runtime dependencies** (dev-only: PHPUnit); Don't add any — it's a selling point.
- **Namespace:** `MiladRahimi\Jwt\` → `src/`, `MiladRahimi\Jwt\Tests\` → `tests/` (PSR-4).

## Commands

```bash
composer install
./vendor/bin/phpunit                               # whole suite
./vendor/bin/phpunit tests/ParserTest.php          # one file
./vendor/bin/phpunit --filter test_simple_example  # one test
```

No `composer test` script. Code style is enforced by PHP_CodeSniffer (`phpcs.xml`) in CI: PSR-12 plus spaced
concatenation, single quotes, short arrays, no-space casts (`(string)$x`), `declare(strict_types=1)` in every
file, a hard 120-character line limit, cyclomatic-complexity/nesting caps, and bans on debug functions and
TODO/FIXME comments. It is not a Composer dependency — run it locally via a downloaded phar (`php phpcs.phar`).
Alpha-ordered imports and no unused imports remain conventions phpcs cannot check — follow them manually.
Static analysis: PHPStan level 10 plus extra strictness flags (`phpstan.neon` — deliberate exclusions are
documented there in comments) runs in CI; it is not a Composer dependency — run it locally via a downloaded
phar (`phpstan analyse`).
Mutation testing: Infection (`infection.json5`) runs in CI at 100% MSI; also phar-only — run it locally via
`XDEBUG_MODE=coverage php infection.phar` (or with pcov). Kill new mutants with tests; add a config ignore
only for provably equivalent mutants, with a comment proving it.
SonarQube Cloud Automatic Analysis (scoped by `.sonarcloud.properties`: `src` + `.github` as sources, `tests`
as tests) decorates PRs with the "SonarCloud Code Analysis" check; its quality gate on new code must pass.
It runs on Sonar's servers — no token, no CI job — and cannot import coverage (Codecov gates coverage instead).
CI runs the suite on PHP 7.4–8.5; keep new code green on 7.4.

## Architecture

A JWT is `base64url(header) . base64url(payload) . base64url(signature)`.
Two facades wire small, single-responsibility pieces by constructor injection:

- **`Generator`** (`src/Generator.php`) — takes a `Signer`, builds the JWT from a claims array.
- **`Parser`** (`src/Parser.php`) — takes a `Verifier` (+ optional `Validator`); splits, checks the header,
  verifies the signature, decodes, then validates claims.
  Also has `verify()` (header + signature) and `validate()` (header + signature + claims).

Each concern is an interface with one default: `Cryptography/Signer` & `Cryptography/Verifier` (per-algorithm),
`Validator/Validator` (`DefaultValidator`), `Json/JsonParser` (`StrictJsonParser`), `Base64/Base64Parser`
(`SafeBase64Parser`).
`VerifierFactory` maps a token's `kid` to a `Verifier` for multi-key setups.

Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — read it before touching cryptography.

## Algorithm layer (`src/Cryptography/`)

- **HMAC** (`HS256/384/512`) — symmetric; one `AbstractHmac` subclass is both `Signer` and `Verifier`
  (`hash_hmac`).
- **RSA** (`RS256/384/512`) — split signer/verifier via `openssl_sign`/`openssl_verify`.
- **RSA-PSS** (`PS256/384/512`) — split; same RSA keys, but EMSA-PSS (RFC 8017) is implemented in-tree
  (`EmsaPss` trait) and OpenSSL only does the raw RSA operation (`OPENSSL_NO_PADDING`).
- **ECDSA** (`ES256/ES256K/ES384/ES512`) — split; OpenSSL **plus** DER↔raw signature conversion (JWS needs raw
  `R||S`).
- **EdDSA / Ed25519** — standalone signer/verifier via libsodium; needs `ext-sodium`. `Ed25519*` subclass the
  `EdDsa*` classes, changing only the `alg` name to the RFC 9864 fully-specified `Ed25519`.
- **Ed448** — RFC 9864, Curve448 via OpenSSL (`openssl_sign`/`openssl_verify` with digest `0`); needs PHP 8.4+
  — the `Ed448*` key classes enforce that by requiring `OPENSSL_KEYTYPE_ED448` at construction.

Keys: string-content (`HmacKey`, `EdDsa*` — `getContent()`) or OpenSSL (`Rsa*`, `Ecdsa*`, `Ed448*` —
`getResource()`, accept a file path **or** inline PEM).

## Conventions

- **PHP 7.4 syntax only in `src/`:** typed properties and `?T` are fine; no enums, `match`, promotion, named
  args, or union types.
  `declare(strict_types=1);` at the top of each file.
- **Line length is 120** for code, comments, and docblocks; never wrap a comment or docblock line before it
  reaches 120 characters.
- **Exceptions** all extend `Exceptions\JwtException`; throw the specific subclass, add no new base classes.
- **Docblock summaries** are third-person indicative and end with a period ("Generates the JWT.", "Checks
  whether…"), not imperative; use `{@inheritDoc}` for inherited members; omit docblocks that only restate a
  typed signature.
- **Exception messages** are complete sentences: capitalized, ending with a period, identifiers in backticks
  (`` `typ` ``). Public-facing message strings are asserted in tests — change message and test together.
- `Enums\PublicClaimNames` is a constants class (not a real enum) — use it instead of literal claim strings.
- **Tests** mirror `src/`, extend `Tests\TestCase`, snake_case names, and also start with
  `declare(strict_types=1);`.
  See [`docs/TESTING.md`](docs/TESTING.md).

## Guardrails

- Never weaken cryptography (verification, DER conversion, key-length checks) to pass a test.
- Keep `src/` dependency-free and PHP 7.4-compatible.
- `assets/keys/` are **test-only** keys — never treat as production keys.
- Don't commit or push unless asked; branch first if on `main`.
- Public-API examples are verified by `tests/ExamplesTest.php` — change README and tests together.

## Known quirks

Documented so they aren't mistaken for bugs; confirm intent before changing.
Detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#known-quirks).

- None at the moment.
