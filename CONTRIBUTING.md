# Contributing to PHP-JWT

Thanks for improving `miladrahimi/php-jwt`.
Deeper references live in [`docs/`](docs/).

## Getting started

```bash
git clone https://github.com/miladrahimi/php-jwt.git
cd php-jwt
composer install
./vendor/bin/phpunit
```

Requirements: PHP `>=7.4`, `ext-openssl`, `ext-json`, and `ext-sodium` (for EdDSA and its tests).

## Ground rules

- **PHP 7.4 is the floor** (CI runs 7.4–8.5).
  No enums, `match`, promotion, named args, or union types in `src/`.
- **No runtime dependencies.**
- `declare(strict_types=1);` at the top of every source file.
- **Don't weaken security-critical code** (signing, verification, format conversion, key handling) to pass tests.
- **KISS** — prefer the simplest thing that works; no extra tooling, configuration, or speculative abstractions
  beyond what the task needs.
- Use `Enums\PublicClaimNames` constants instead of raw claim strings.

## Code style

- Lines are at most 120 characters — code, comments, and docblocks alike.
- Don't wrap a comment or docblock line before it reaches the 120-character limit; let sentences run the full
  width first.
- [StyleCI](https://styleci.io) enforces the rest (see `.styleci.yml`): PSR-12 plus spaced concatenation,
  alphabetically ordered imports, single quotes, short arrays, and no unused imports.

## Tests

Add tests for every change; the suite mirrors `src/` and extends `Tests\TestCase` with snake_case names.
Conventions and templates: [`docs/TESTING.md`](docs/TESTING.md).
Public-API examples in the README are verified by `tests/ExamplesTest.php` — update both together.

## Pull requests

1. Branch off `main`, one concern per PR.
2. Ensure `./vendor/bin/phpunit` is green (ideally on PHP 7.4).
3. Ensure `phpstan analyse` (level 8, `phpstan.neon`) reports no errors — CI runs it too.
4. Update the README and `docs/` when behavior or the public API changes.

## Read more

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design, component map, cryptography, known quirks.
- [`docs/TESTING.md`](docs/TESTING.md) — test layout and conventions.
- [`docs/ADDING_AN_ALGORITHM.md`](docs/ADDING_AN_ALGORITHM.md) — extending the cryptography layer.

Contributions are licensed under the project's [MIT License](LICENSE).
