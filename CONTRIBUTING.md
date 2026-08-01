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

Requirements: PHP `>=7.4`, `ext-openssl`, `ext-json`, and `ext-sodium` (for EdDSA/Ed25519 and their tests).
The Ed448 algorithm and its tests additionally need PHP 8.4+ with OpenSSL Ed448 support.

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
- [PHP_CodeSniffer](https://github.com/PHPCSStandards/PHP_CodeSniffer) enforces the rest (see `phpcs.xml`):
  PSR-12 plus spaced concatenation, single quotes, short arrays, no-space casts (`(string)$x`), and
  `declare(strict_types=1);` in every file. It is phar-only (like PHPStan and Infection) — run `php phpcs.phar`
  locally.
- Keep imports alphabetically ordered and remove unused ones — phpcs has no core sniff for these, so they are
  reviewed manually.
- Trailing inline comments sit exactly one space after the code — don't column-align them. Enforced by the
  project-local `PhpJwt.WhiteSpace.SingleSpaceBeforeInlineComment` sniff (in `phpcs/`).

## Tests

Add tests for every change; the suite mirrors `src/` and extends `Tests\TestCase` with snake_case names.
Conventions and templates: [`docs/TESTING.md`](docs/TESTING.md).
Public-API examples in the README are verified by `tests/ExamplesTest.php` — update both together.

## Pull requests

1. Branch off `main`, one concern per PR.
2. Ensure `./vendor/bin/phpunit` is green (ideally on PHP 7.4).
3. Ensure `phpstan analyse` (level 10, `phpstan.neon`) reports no errors — CI runs it too.
4. Ensure `phpcs` (`phpcs.xml`) reports no violations — CI runs it too.
5. Ensure `infection` (mutation testing, `infection.json5`) reports a 100% MSI — CI runs it too.
6. Update the README and `docs/` when behavior or the public API changes.

### Authorship

Commits and pull requests are attributed to their human author only. Don't add AI assistants or agents as
co-authors or collaborators: no `Co-Authored-By:` trailers naming AI tools, and no AI agent names in commit
messages, PR descriptions, or commit metadata. Using AI tooling to help produce a change is fine — the
authorship of, and the responsibility for, the change stay with you.

## Read more

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design, component map, cryptography, known quirks.
- [`docs/TESTING.md`](docs/TESTING.md) — test layout and conventions.
- [`docs/ADDING_AN_ALGORITHM.md`](docs/ADDING_AN_ALGORITHM.md) — extending the cryptography layer.

Contributions are licensed under the project's [MIT License](LICENSE).
