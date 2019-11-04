[![Latest Stable Version](https://poser.pugx.org/miladrahimi/php-jwt/v/stable)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Total Downloads](https://poser.pugx.org/miladrahimi/php-jwt/downloads)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Build Status](https://travis-ci.org/miladrahimi/php-jwt.svg?branch=master)](https://travis-ci.org/miladrahimi/php-jwt)
[![Coverage Status](https://coveralls.io/repos/github/miladrahimi/php-jwt/badge.svg?branch=master)](https://coveralls.io/github/miladrahimi/php-jwt?branch=master)
[![License](https://poser.pugx.org/miladrahimi/php-jwt/license)](https://packagist.org/packages/miladrahimi/php-jwt)

# PHP-JWT

A PHP implementation of JWT (JSON Web Token) generator, parser, verifier, and validator.

## Overview

PHP-JWT is a package written in PHP programming language to encode (generate), decode (parse), verify and validate JWTs 
(JSON Web Tokens).

## Documentation

### Installation

Add the package to your Composer dependencies with the following command:

```bash
composer require miladrahimi/php-jwt "1.*"
```

Now, you are ready to use the package!

### What is JWT?

In case you are unfamiliar with JWT you can read [Wikipedia](https://en.wikipedia.org/wiki/JSON_Web_Token) or 
[JWT.io](https://jwt.io).

### HMAC Algorithms

If you want to use a single key to both generate and parse tokens, you should use HMAC algorithms (HS256, HS384, or HS512). These algorithms use the same key to sign and verify tokens. Take a look at the example below.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;

$key = '12345678901234567890123456789012';
$signer = new HS256($key);

$generator = new JwtGenerator($signer);

$jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

$parser = new JwtParser($signer);

$claims = $parser->parse($jwt);

echo $claims; // ['sub' => 1, 'jti' => 2]
```

### RSA Algorithms

If you want to use an asymmetric key to generate and parse tokens,
you should use RSA algorithms (RS256, RS384, or RS512).
These algorithms use a pair (public and private) key,
the signer uses the private key and the verifier uses the public key.
These algorithms could be useful if the authentication server and the resource owner belong to different vendors and
they are not trusted by each other.
Take a look at the example below.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;

$privateKey = new PrivateKey('files/keys/private.pem');
$publicKey = new PublicKey('files/keys/public.pem');

$signer = new RS256Signer($privateKey);
$verifier = new RS256Verifier($publicKey);

$generator = new JwtGenerator($signer);
$jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

$parser = new JwtParser($verifier);
$claims = $parser->parse($jwt);

echo $claims; // ['sub' => 1, 'jti' => 2]
```

You can read [this instruction](https://en.wikibooks.org/wiki/Cryptography/Generate_a_keypair_using_OpenSSL) to learn how to generate a pair (public/private) key.

### More about Token Generating

As the examples above illustrate, you can generate JWTs with the `generate()` method in the `JwtGenerator` class.
The `JwtGenerator` class requires a signer to sign tokens. You can use HMAC or RSA signers to generate tokens.
HMAC signers use a string key and RSA signers use a private key file,
they throw an `InvalidKeyException` exception when the provided key is not valid.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

try {
    $privateKey = new PrivateKey('keys/private.pem');
} catch(InvalidKeyException $e) {
    // Your key is invalid.
}

$signer = new RS256Signer($privateKey);

$generator = new JwtGenerator($signer);
$jwt = $generator->generate(['sub' => 1, 'jti' => 2]);
```

You can also provide your custom JSON and Base64 parser for the `JwtGenerator` class!

### Verification and Validation

Before extracting Claims from a token, you should verify and validate the token. First, we verify the token's signature to make sure that an original issuer has generated the token. Then, we should validate the JWT's Claims. `exp`, `iat`, and `nbf` are the Claims to should be validated. Private claims also could be validated based on your application requirements.

The `parse()` method in the `JwtParser` class verifies tokens, validates Claims, and extracts the JWT's claims.
If you don't need to extract Claims, and only need to verify and validate it, you can use the `validate()` method.
And if you only need to verify the token's signature, you can use the `verifySignature()` method.

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS512;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;
use MiladRahimi\Jwt\Exceptions\TokenParsingException

$jwt = // Read token from the request header...

$key = '12345678901234567890123456789012';
$verifyer = new HS512($key);

$parser = new JwtParser($verifyer);

try {
    $claims = $parser->parse($jwt);
    
    // token is valid...
} catch (TokenParsingException $e) {
    // token is not valid...
}
```

The mentioned methods in `JwtParser` throw `InvalidSignatureException` exception when the token's signature is invalid.

The `validate()` and `parse()` method throws `ValidationException` when the token claims are invalid, `InvalidJsonException` exception when could not parse JSON, and `InvalidTokenException` when the token format was invalid (for example it does not consist of three parts).

All these exceptions are a subclass of  `TokenParsingException`, so if the failure reason is not important, you can only catch this exception.

### Custom Validation

The `JwtParser` uses the `DefaultValidator` to validate tokens in the `parse()` and `validate()` methods. This validator takes care of `exp`, `iat` and `nbf` claims when they are present in the payload.

You can also create an instance of `DefaultValidator` or `Validator` (an empty validator with no rule) and add your own rules like this example:

```php
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS512;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;
use MiladRahimi\Jwt\Exceptions\TokenParsingException
use MiladRahimi\Jwt\Validator\Rules\Required\Exists;
use MiladRahimi\Jwt\Validator\Rules\Required\ConsistsOf;
use MiladRahimi\Jwt\Validator\Rules\Required\NewerThan;

$jwt = // Read from header...

$verifyer = new HS512('some random key');

$validator = new DefaultValidator();

// "iss" must exist.
$validator->addRule('iss', new Exists());

// "aud" must consist of the word "Company"
$validator->addRule('aud', new ConsistsOf('Company'));

// "future-time" must be a time in future (newer than now!)
$validator->addRule('future-time', new NewerThan(time()));

$parser = new JwtParser($verifyer, $validator);

try {
    $claims = $parser->parse($jwt);
    
    // token is valid...
} catch (TokenParsingException $e) {
    // token is not valid...
}
```

As you can see in the snippet above, you can instantiate a validator and add your own rules to it.
To add a new rule, you must pass the Claim name you are setting rule for and the rule object.
A rule is an instance of rule classes. There are two major categories of rules, optional and required.
The optional rules would be checked only when the Claim was present, but the required rules would fail when the Claim wasn't present.

There are plenty of built-in rules, but you can also create your own rules by implementing the `Rule` interface.

## License
PHP-JWT is initially created by [Milad Rahimi](http://miladrahimi.com)
and released under the [MIT License](http://opensource.org/licenses/mit-license.php).
