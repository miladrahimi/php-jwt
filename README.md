[![Latest Stable Version](https://poser.pugx.org/miladrahimi/php-jwt/v/stable)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Total Downloads](https://poser.pugx.org/miladrahimi/php-jwt/downloads)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Build](https://github.com/miladrahimi/php-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/miladrahimi/php-jwt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/miladrahimi/php-jwt/graph/badge.svg?token=KctrYUweFd)](https://codecov.io/gh/miladrahimi/php-jwt)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/miladrahimi/php-jwt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/miladrahimi/php-jwt/?branch=master)
[![License](https://poser.pugx.org/miladrahimi/php-jwt/license)](https://packagist.org/packages/miladrahimi/php-jwt)

# PHP-JWT

PHP-JWT is a PHP package built for encoding (generating), decoding (parsing), verifying, and validating JSON Web Tokens (JWTs).
Its design emphasizes a fluent, user-friendly, and object-oriented interface, crafted with performance in mind.

Supported algorithms:
* HMAC: `HS256`, `HS384`, and `HS512`
* RSA: `RS256`, `RS384`, and `RS512`
* ECDSA: `ES256`, `ES256K`, and `RS384`
* EdDSA: `EdDSA`

Supported features:
* Built-in and custom validations
* Multiple key and `kid` header handler

Confirmed by [JWT.io](https://jwt.io).

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

### ECDSA Algorithms

The ECDSA algorithm, similar to RSA, operates asymmetrically, providing even stronger security measures than RSA.
The PHP-JWT package supports `ES256`, `ES256K`, and `RS384` ECDSA algorithms.
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

## EdDSA Algorithm

EdDSA, similar to RSA and ECDSA, is an asymmetric cryptography algorithm and is widely recommended.
In order to utilize it, ensure that the `sodium` PHP extension is installed in your environment.
The following example demonstrates how to use it.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaSigner;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaVerifier;
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

### Validation

By default, the package validates certain public claims if present (using `DefaultValidator`), and parses the claims.
If you have custom claims, you can include their validation rules as well.
Check out this example:

```php
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;

$jwt = '...'; // Get the JWT from the user

$signer = new HS256(new HmacKey('12345678901234567890123456789012'));

// Extend the DefaultValidator
$validator = new DefaultValidator();

// The 'is-admin' claim is required, without it or a mismatched rule, validation fails.
$validator->addRequiredRule('is-admin', new EqualsTo(true));

// The 'exp' claim is optional, and the rule will be applicable if it is present.
$validator->addOptionalRule('exp', new NewerThan(time()), false);

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

* [ConsistsOf](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/ConsistsOf.php)
* [EqualsTo](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/EqualsTo.php)
* [GreaterThan](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/GreaterThan.php)
* [GreaterThanOrEqualTo](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/GreaterThanOrEqualTo.php)
* [IdenticalTo](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/IdenticalTo.php)
* [LessThan](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/LessThan.php)
* [LessThanOrEqualTo](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/LessThanOrEqualTo.php)
* [NewerThan](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/NewerThan.php)
* [NewerThanOrSame](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/NewerThanOrSame.php)
* [NotEmpty](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/NotEmpty.php)
* [NotNull](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/NotNull.php)
* [OlderThan](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/OlderThan.php)
* [OlderThanOrSame](https://github.com/miladrahimi/php-jwt/blob/master/src/Validator/Rules/OlderThanOrSame.php)

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

$privateKey1 = new RsaPrivateKey('/path/to/rsa-private.pem', '', 'key-1');
$publicKey1 = new RsaPublicKey('/path/to/rsa-public.pem', 'key-1');

$privateKey2 = new EcdsaPrivateKey('/path/to/ecdsa384-private.pem', '', 'key-2');
$publicKey2 = new EcdsaPublicKey('/path/to/ecdsa384-public.pem', 'key-2');

// Generate tokens

$signer1 = new RS256Signer($privateKey1);
$generator1 = new Generator($signer1);
$jwt1 = $generator1->generate(['id' => 13, 'is-admin' => true]);
// $jwt1 header: {"alg": "RS256", "typ": "JWT", "kid": "key-1"}

$signer2 = new ES384Signer($privateKey2);
$generator2 = new Generator($signer2);
$jwt2 = $generator2->generate(['id' => 13, 'is-admin' => true]);
// $jwt2 header: {"alg": "ES384", "typ": "JWT", "kid": "key-2"}

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
PHP-JWT is initially created by [Milad Rahimi](http://miladrahimi.com)
and released under the [MIT License](http://opensource.org/licenses/mit-license.php).
