[![Latest Stable Version](https://poser.pugx.org/miladrahimi/php-jwt/v/stable)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Total Downloads](https://poser.pugx.org/miladrahimi/php-jwt/downloads)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Build](https://github.com/miladrahimi/php-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/miladrahimi/php-jwt/actions/workflows/ci.yml)
[![Mutation](https://img.shields.io/badge/Mutation-100%25-brightgreen)](https://github.com/miladrahimi/php-jwt/actions/workflows/mutation.yml)
[![codecov](https://codecov.io/gh/miladrahimi/php-jwt/graph/badge.svg?token=KctrYUweFd)](https://codecov.io/gh/miladrahimi/php-jwt)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=miladrahimi_php-jwt&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=miladrahimi_php-jwt)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-10-brightgreen)](https://phpstan.org/)

# PHP-JWT

PHP-JWT is a PHP package built for encoding (generating), decoding (parsing), verifying, and validating JSON Web Tokens (JWTs).
Its design emphasizes a fluent, user-friendly, and object-oriented interface, crafted with performance in mind.

> This package is listed in the official [JWT.io](https://www.jwt.io/libraries?programming_language=php) PHP libraries directory.

Supported algorithms:
* **HMAC**: `HS256`, `HS384`, and `HS512`
* **RSA**: `RS256`, `RS384`, and `RS512`
* **RSA-PSS**: `PS256`, `PS384`, and `PS512`
* **ECDSA**: `ES256`, `ES256K`, `ES384`, and `ES512`
* **EdDSA**: `EdDSA` and `Ed25519` (require the `sodium` PHP extension), and `Ed448` (requires PHP 8.4+)

Supported features:
* Built-in and custom validations
* Multiple keys and `kid` header handling

## Documentation

### What is JWT?

If you're not familiar with JWTs, you can refer to the [Wikipedia page](https://en.wikipedia.org/wiki/JSON_Web_Token) or visit [JWT.io](https://jwt.io) for more information.

### Installation

Include the package in your Composer dependencies using the following command:

```bash
composer require miladrahimi/php-jwt "3.*"
```

### Quick Start

Here's an example demonstrating how to generate a JWT and parse it using the `HS256` algorithm:

```php
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;

// Use HS256 to generate and parse JWTs
$key = new HmacKey('12345678901234567890123456789012');
$signer = new HS256($key);

// Generate a JWT
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

print_r($jwt); // "abc.123.xyz"

// Parse the token
$parser = new Parser($signer);
$claims = $parser->parse($jwt);

print_r($claims); // ['id' => 13, 'is-admin' => true]
```

> **Runnable examples:** the [`examples/`](examples) directory has a self-contained script per algorithm
> using the sample keys in `assets/keys/`.
> Run one with e.g. `php examples/rs256.php`, and swap in your own key where marked.

### HMAC Algorithms

HMAC algorithms rely on symmetric keys, allowing a single key to encode (sign) and decode (verify) JWTs.
The PHP-JWT package supports `HS256`, `HS384`, and `HS512` HMAC algorithms.
The example above showcases the utilization of an HMAC algorithm to both sign and verify a JWT.

### RSA Algorithms

RSA algorithms work with pairs of keys: a private key for signing JWTs and a corresponding public key for verification.
This method is useful when the authentication server can't completely trust resource owners.
The PHP-JWT package supports `RS256`, `RS384`, and `RS512` RSA algorithms.
The example below demonstrates this process.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// Generate a token
$privateKey = new RsaPrivateKey('/path/to/private.pem');
$signer = new RS256Signer($privateKey);
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

print_r($jwt); // "abc.123.xyz"

// Parse the token
$publicKey = new RsaPublicKey('/path/to/public.pem');
$verifier = new RS256Verifier($publicKey);
$parser = new Parser($verifier);
$claims = $parser->parse($jwt);

print_r($claims); // ['id' => 13, 'is-admin' => true]
```

You can refer to [this instruction](https://en.wikibooks.org/wiki/Cryptography/Generate_a_keypair_using_OpenSSL) to learn how to generate a pair of RSA keys using OpenSSL.

### RSA-PSS Algorithms

The RSA-PSS algorithms sign with the same RSA key pairs as the RS* family but use the probabilistic PSS padding
scheme (RFC 8017), which is the padding modern standards recommend for new applications.
The PHP-JWT package supports `PS256`, `PS384`, and `PS512` RSA-PSS algorithms.
The example below demonstrates this process.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// Generate a token
$privateKey = new RsaPrivateKey('/path/to/private.pem');
$signer = new PS256Signer($privateKey);
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

print_r($jwt); // "abc.123.xyz"

// Parse the token
$publicKey = new RsaPublicKey('/path/to/public.pem');
$verifier = new PS256Verifier($publicKey);
$parser = new Parser($verifier);
$claims = $parser->parse($jwt);

print_r($claims); // ['id' => 13, 'is-admin' => true]
```

Please note that `PS256` signatures are randomized by design: signing the same claims twice produces different
tokens, and both verify.

### ECDSA Algorithms

The ECDSA algorithm, similar to RSA, operates asymmetrically, providing even stronger security measures than RSA.
The PHP-JWT package supports `ES256`, `ES256K`, `ES384`, and `ES512` ECDSA algorithms.
The example below demonstrates this process.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// Generate a token
$privateKey = new EcdsaPrivateKey('/path/to/private.pem');
$signer = new ES384Signer($privateKey);
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

print_r($jwt); // "abc.123.xyz"

// Parse the token
$publicKey = new EcdsaPublicKey('/path/to/public.pem');
$verifier = new ES384Verifier($publicKey);
$parser = new Parser($verifier);
$claims = $parser->parse($jwt);

print_r($claims); // ['id' => 13, 'is-admin' => true]
```

### EdDSA Algorithm

EdDSA, similar to RSA and ECDSA, is an asymmetric cryptography algorithm and is widely recommended.
In order to utilize it, ensure that the `sodium` PHP extension is installed in your environment.
The following example demonstrates how to use it.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaSigner;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaVerifier;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// Generate a token
$privateKey = new EdDsaPrivateKey(base64_decode(file_get_contents('/path/to/ed25519.sec')));
$signer = new EdDsaSigner($privateKey);
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

print_r($jwt); // "abc.123.xyz"

// Parse the token
$publicKey = new EdDsaPublicKey(base64_decode(file_get_contents('/path/to/ed25519.pub')));
$verifier = new EdDsaVerifier($publicKey);
$parser = new Parser($verifier);
$claims = $parser->parse($jwt);

print_r($claims); // ['id' => 13, 'is-admin' => true]
```

Please note that EdDSA keys must be in string format. If they are already base64 encoded, decoding them is necessary before use.

### Ed25519 Algorithm

[RFC 9864](https://datatracker.ietf.org/doc/rfc9864/) replaces the `EdDSA` algorithm name with the fully-specified names `Ed25519` and `Ed448`.
`Ed25519` uses the exact same keys and signatures as `EdDSA` above; only the token's `alg` header differs.
It also requires the `sodium` PHP extension.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed25519Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed25519Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// Generate a token
$privateKey = new EdDsaPrivateKey(base64_decode(file_get_contents('/path/to/ed25519.sec')));
$signer = new Ed25519Signer($privateKey);
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

// Parse the token
$publicKey = new EdDsaPublicKey(base64_decode(file_get_contents('/path/to/ed25519.pub')));
$verifier = new Ed25519Verifier($publicKey);
$parser = new Parser($verifier);
$claims = $parser->parse($jwt);

print_r($claims); // ['id' => 13, 'is-admin' => true]
```

### Ed448 Algorithm

`Ed448` (RFC 9864) is EdDSA over Curve448.
It runs on OpenSSL instead of Sodium and requires PHP 8.4 or later; on older PHP versions, creating the keys throws an exception.
The keys are PEM files (or inline PEM strings), which you can generate with the OpenSSL CLI:

```shell
openssl genpkey -algorithm ED448 -out ed448-private.pem
openssl pkey -in ed448-private.pem -pubout -out ed448-public.pem
```

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed448Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed448Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\Ed448PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\Ed448PublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// Generate a token
$privateKey = new Ed448PrivateKey('/path/to/ed448-private.pem');
$signer = new Ed448Signer($privateKey);
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

// Parse the token
$publicKey = new Ed448PublicKey('/path/to/ed448-public.pem');
$verifier = new Ed448Verifier($publicKey);
$parser = new Parser($verifier);
$claims = $parser->parse($jwt);

print_r($claims); // ['id' => 13, 'is-admin' => true]
```

### Validation

By default, the package validates certain public claims if present (using `DefaultValidator`), and parses the claims.
If you have custom claims, you can include their validation rules as well.
Check out this example:

```php
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\DefaultValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;
use MiladRahimi\Jwt\Validator\Rules\NewerThan;

$jwt = '...'; // Get the JWT from the user

$signer = new HS256(new HmacKey('12345678901234567890123456789012'));

// Extend the DefaultValidator
$validator = new DefaultValidator();

// The 'is-admin' claim is required, without it or a mismatched rule, validation fails.
$validator->addRequiredRule('is-admin', new EqualsTo(true));

// The 'exp' claim is optional, and the rule will be applicable if it is present.
$validator->addOptionalRule('exp', new NewerThan(time()));

// Parse the token
$parser = new Parser($signer, $validator);

try {
    $claims = $parser->parse($jwt);
    print_r($claims); // ['id' => 13, 'is-admin' => true]
} catch (ValidationException $e) {
    // Handle error.
}
```

In the aforementioned example, we extended `DefaultValidator`, which comes with pre-defined Rules for public claims.
We strongly suggest extending it for your validation.
Note that `DefaultValidator` is a subclass of `BaseValidator`.
While you can utilize `BaseValidator` for your validations, opting for this means losing the built-in Rules, requiring you to manually add all the Rules yourself.

#### Rules

Validators rely on Rules to validate claims, with each Rule specifying acceptable values for a claim.
You can access the built-in Rules within the `MiladRahimi\Jwt\Validator\Rules` namespace.

* [ConsistsOf](src/Validator/Rules/ConsistsOf.php)
* [EqualsTo](src/Validator/Rules/EqualsTo.php)
* [GreaterThan](src/Validator/Rules/GreaterThan.php)
* [GreaterThanOrEqualTo](src/Validator/Rules/GreaterThanOrEqualTo.php)
* [IdenticalTo](src/Validator/Rules/IdenticalTo.php)
* [LessThan](src/Validator/Rules/LessThan.php)
* [LessThanOrEqualTo](src/Validator/Rules/LessThanOrEqualTo.php)
* [NewerThan](src/Validator/Rules/NewerThan.php)
* [NewerThanOrSame](src/Validator/Rules/NewerThanOrSame.php)
* [NotEmpty](src/Validator/Rules/NotEmpty.php)
* [NotNull](src/Validator/Rules/NotNull.php)
* [OlderThan](src/Validator/Rules/OlderThan.php)
* [OlderThanOrSame](src/Validator/Rules/OlderThanOrSame.php)

Descriptions for each Rule can be found within their respective class doc blocks.

#### Custom Rules

If the provided built-in Rules don't fulfill your requirements, you can create custom Rules.
To do so, implement the `Rule` interface.
For instance, consider the `Even` Rule below, designed to verify whether a given claim represents an even number:

```php
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

class Even implements Rule
{
    public function validate(string $name, $value)
    {
        if ($value % 2 != 0) {
            throw new ValidationException("The `$name` must be an even number.");
        }
    }
}
```

### Verifying Without Parsing

When you only need to check a token, the `Parser` offers lighter entry points than `parse()`:

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Parser;

$signer = new HS256(new HmacKey('12345678901234567890123456789012'));
$parser = new Parser($signer);

$parser->verify($jwt);   // Validates the header and verifies the signature
$parser->validate($jwt); // Additionally validates the claims (like parse(), without returning them)
```

All entry points validate the header (`typ` must be an accepted type — `JWT` by default; `alg` and `kid`,
when present, must match the verifier)
and verify the signature before anything else; they throw a `JwtException` subclass on any failure.

### Token Types

The `typ` header is `JWT` by default; the `Generator` can stamp another type and the `Parser` can accept others:

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

$signer = new HS256(new HmacKey('12345678901234567890123456789012'));

// Issue an OAuth 2.0 access token (RFC 9068)
$generator = new Generator($signer, null, null, 'at+jwt');
$jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

// Accept only `at+jwt` tokens; pass several types (e.g. ['JWT', 'at+jwt']) to accept any of them
$parser = new Parser($signer, null, null, null, ['at+jwt']);
$claims = $parser->parse($jwt);
```

Comparison is case-insensitive and `application/`-prefix-aware per RFC 7515 (`at+jwt` ≡ `application/at+jwt`);
pin a single type when possible.

### Multiple Keys

The `kid` parameter within the JWT header plays a crucial role in managing multiple keys efficiently.
By leveraging the "kid" header, you can assign a unique key identifier (kid) to each key that you use to sign JWTs.
This enables seamless verification of JWTs by associating them with their respective key identifiers (kid).
Check out this example:

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\VerifierFactory;

$privateKey1 = new RsaPrivateKey('/path/to/rsa-private.pem', '', 'key-1');
$publicKey1 = new RsaPublicKey('/path/to/rsa-public.pem', 'key-1');

$privateKey2 = new EcdsaPrivateKey('/path/to/ecdsa384-private.pem', '', 'key-2');
$publicKey2 = new EcdsaPublicKey('/path/to/ecdsa384-public.pem', 'key-2');

// Generate tokens

$signer1 = new RS256Signer($privateKey1);
$generator1 = new Generator($signer1);
$jwt1 = $generator1->generate(['id' => 13, 'is-admin' => true]);
// $jwt1 header: {"typ": "JWT", "alg": "RS256", "kid": "key-1"}

$signer2 = new ES384Signer($privateKey2);
$generator2 = new Generator($signer2);
$jwt2 = $generator2->generate(['id' => 13, 'is-admin' => true]);
// $jwt2 header: {"typ": "JWT", "alg": "ES384", "kid": "key-2"}

// Parse tokens

$verifierFactory = new VerifierFactory([
    new RS256Verifier($publicKey1),
    new ES384Verifier($publicKey2),
]);

$verifier1 = $verifierFactory->getVerifier($jwt1); // instance of RS256Verifier
$parser1 = new Parser($verifier1);
$claims1 = $parser1->parse($jwt1);
print_r($claims1); // ['id' => 13, 'is-admin' => true]

$verifier2 = $verifierFactory->getVerifier($jwt2); // instance of ES384Verifier
$parser2 = new Parser($verifier2);
$claims2 = $parser2->parse($jwt2);
print_r($claims2); // ['id' => 13, 'is-admin' => true]
```

### Error Handling

Here are the exceptions that the package might throw:

* Encoding:
  * [InvalidKeyException](src/Exceptions/InvalidKeyException.php) when the provided key is not valid.
  * [JsonEncodingException](src/Exceptions/JsonEncodingException.php) when cannot convert the provided claims to JSON.
  * [SigningException](src/Exceptions/SigningException.php) when cannot sign the token using the provided signer or key.
* Decoding:
  * [InvalidTokenException](src/Exceptions/InvalidTokenException.php) when the JWT format is not valid (for example, it has no payload).
  * [InvalidSignatureException](src/Exceptions/InvalidSignatureException.php) when the JWT signature is not valid.
  * [JsonDecodingException](src/Exceptions/JsonDecodingException.php) when the JSON extracted from JWT is not valid.
  * [ValidationException](src/Exceptions/ValidationException.php) when at least one of the validation rules fails.
* Finding Verifier:
  * [NoKidException](src/Exceptions/NoKidException.php) when there is no `kid` in the token header.
  * [VerifierNotFoundException](src/Exceptions/VerifierNotFoundException.php) when no key/verifier matches the `kid` in the token header.

All of the exceptions mentioned are subclasses of the [JwtException](src/Exceptions/JwtException.php) exception.
By catching `JwtException`, you can handle all these cases collectively instead of catching each one individually.

## License

PHP-JWT is released under the [MIT License](http://opensource.org/licenses/mit-license.php).
