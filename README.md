[![Latest Stable Version](https://poser.pugx.org/miladrahimi/php-jwt/v/stable)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Total Downloads](https://poser.pugx.org/miladrahimi/php-jwt/downloads)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Build](https://github.com/miladrahimi/php-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/miladrahimi/php-jwt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/miladrahimi/php-jwt/graph/badge.svg?token=KctrYUweFd)](https://codecov.io/gh/miladrahimi/php-jwt)
[![License](https://poser.pugx.org/miladrahimi/php-jwt/license)](https://packagist.org/packages/miladrahimi/php-jwt)

# PHP-JWT

PHP-JWT is a PHP programming language package designed for encoding (generation), decoding (parsing), verification, and validation of JSON Web Tokens (JWTs).
Featuring a fluent, user-friendly, and object-oriented interface.

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
$signer = new HS256('12345678901234567890123456789012');

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

HMAC algorithms indeed rely on symmetric keys, allowing a single key to both sign and verify JWTs.
This package supports HS256, HS384, and HS512 HMAC algorithms.
The example above showcases the utilization of an HMAC algorithm (HS256) to both sign and verify a JWT.

### RSA Algorithms

RSA algorithms work with pairs of keys: a private key for signing JWTs and a corresponding public key for verification.
This method is useful when the authentication server can't completely trust resource owners.
This package supports RS256, RS384, and RS512 RSA algorithms.
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

You can refer to [this instruction](https://en.wikibooks.org/wiki/Cryptography/Generate_a_keypair_using_OpenSSL) to learn how to generate a pair of RSA keys,
one for public use and the other for private use, using OpenSSL.

### ECDSA Algorithms

The ECDSA algorithm, like RSA, operates asymmetrically, providing a comparably secure solution while offering heightened security measures.
This package supports ES256, ES256K, and RS384 ECDSA algorithms.
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

### Validation

In default, the package verifies the JWT signature, validates some of the public claims if they exist (using `DefaultValidator`), and parse the claims.
If you have your custom claims, you can add their validation rules, as well.
See this example:

```php
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;

$jwt = '...'; // Get the JWT from the user

$signer = new HS256('12345678901234567890123456789012');

// Add Validation (Extend the DefaultValidator)
$validator = new DefaultValidator();
$validator->addRule('is-admin', new EqualsTo(true));

// Parse the token
$parser = new Parser($signer, $validator);

try {
    $claims = $parser->parse($jwt);
    echo $claims; // ['id' => 666, 'is-admin' => true]
} catch (ValidationException $e) {
    // Handle error.
}
```

In the example above, we extended `DefaultValidator`.
This validator has some built-in Rules for public claims.
We also recommend you extend it for your validation.
The `DefaultValidator` is a subclass of the `BaseValidator`.
You can also use the `BaseValidator` for your validations, but you will lose the built-in Rules, and you have to add all the Rules by yourself.

#### Rules

Validators use the Rules to validate the claims.
Each Rule determines eligible values for a claim.
These are the built-in Rules you can find under the namespace `MiladRahimi\Jwt\Validator\Rules`:

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

You can see their description in their class doc-blocks.

#### Required and Optional Rules

You can add a rule to a validator as required or optional.
If the Rule is required, validation will fail when the related claim is not present in the JWT claims.

This example demonstrates how to add rules as required and optional:

```php
$validator = new DefaultValidator();

// Add a rule as required
$validator->addRule('exp', new NewerThan(time()));

// Add a rule as required again!
$validator->addRule('exp', new NewerThan(time()), true);

// Add a rule as optional
$validator->addRule('exp', new NewerThan(time()), false);
```

#### Custom Rules

You create your own Rules if the built-in ones cannot meet your needs.
To create a Rule, you must implement the `Rule` interface like the following example that shows the `Even` Rule which is going to check if the given claim is an even number or not:

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

### Error Handling

Here are the exceptions that the package throw:
* `InvalidKeyException`:
  * By `Generator` and `Parser` methods.
  * When the provided key is not valid.
* `InvalidSignatureException`:
  * By `Parser::parse()`, `Parser::verify()`, and `Parser::validate()` methods.
  * When the JWT signature is not valid.
* `InvalidTokenException`:
  * By `Parser::parse()`, `Parser::verify()`, and `Parser::validate()` methods.
  * When the JWT format is not valid (for example it has no payload).
* `JsonDecodingException`:
  * By `Parser::parse()` and `Parser::validate()` methods.
  * When the JSON extracted from JWT is not valid.
* `JsonEncodingException`:
  * By `Generator::generate()` method.
  * When cannot convert the provided claims to JSON.
* `SigningException`:
  * By `Generator::generate()` method.
  * When cannot sign the token using the provided signer or key.
* `ValidationException`:
  * By `Parser::parse()` and `Parser::validate()` methods.
  * When one of the validation rules fail.

## License
PHP-JWT is initially created by [Milad Rahimi](http://miladrahimi.com)
and released under the [MIT License](http://opensource.org/licenses/mit-license.php).
