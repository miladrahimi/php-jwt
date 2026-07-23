# Testing

## Running

```bash
./vendor/bin/phpunit                               # whole suite (testsuite "main")
./vendor/bin/phpunit tests/ParserTest.php          # one file
./vendor/bin/phpunit --filter test_simple_example  # one test
```

`phpunit.xml` defines one testsuite `main` → `./tests`, coverage over `./src`.
There is no `composer test` script — call the binary directly.
Local coverage without pcov/xdebug: `phpdbg -qrr vendor/bin/phpunit --coverage-text`.
EdDSA tests need `ext-sodium`.
CI runs on PHP 7.4–8.5; new tests must pass on 7.4.

## Layout

`tests/` mirrors `src/`.
`src/Foo/Bar.php` → `tests/Foo/BarTest.php`, namespace `MiladRahimi\Jwt\Tests\Foo`.

## Base `TestCase`

Every test extends `MiladRahimi\Jwt\Tests\TestCase` (not PHPUnit's directly).
It provides via `setUp()`:

- `$sampleClaims` — canonical claims (`sub`, `exp`, `nbf`, `iat`, `iss`), keyed by `PublicClaimNames`.
- `$sampleJwt` — a precomputed HS256 token for `$sampleClaims`, secret `'12345678901234567890123456789012'`.

Override `setUp()` only by calling `parent::setUp()` first.

## Conventions

- Each test file starts with `declare(strict_types=1);` (same as `src/`).
- Method names: snake_case, `test_<action>_it_should_<expectation>`; getters use `test_set_and_get_<thing>`.
- Methods that throw carry `@throws Throwable`.
- "No exception" success paths end with `$this->assertTrue(true)`.
- Value checks use `assertEquals`; strict/identity checks use `assertSame`.
- Failure paths use `expectException(...)`, plus `expectExceptionMessage(...)` /
  `expectExceptionMessageMatches(...)` where the message matters.

## Key assets (`assets/keys/`)

Test-only keys: `rsa-*.pem`, `ecdsa256/256k/384/512` pairs, `ed25519.sec`/`.pub` (raw base64 — decode before
use), and `assets/file.empty` for invalid-key cases.
Reference PEM keys by `__DIR__`-relative path (depth varies by nesting).

> ⚠️ These are test keys only — never treat them as production keys.

## Templates

- **Algorithm** (`tests/Cryptography/Algorithms/<Family>/`): sign-then-verify (ends `assertTrue(true)`), a
  mismatched-plaintext case expecting `InvalidSignatureException`, plus getter checks.
- **Key** (`tests/Cryptography/Keys/`): valid-from-file and valid-from-string both non-null, `test_id`, and
  invalid path/file cases expecting `InvalidKeyException`.
- **End-to-end**: add a round-trip to `tests/ExamplesTest.php` when changing a README example.
