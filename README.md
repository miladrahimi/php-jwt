[![Latest Stable Version](https://poser.pugx.org/miladrahimi/php-jwt/v/stable)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Total Downloads](https://poser.pugx.org/miladrahimi/php-jwt/downloads)](https://packagist.org/packages/miladrahimi/php-jwt)
[![Build Status](https://travis-ci.org/miladrahimi/php-jwt.svg?branch=master)](https://travis-ci.org/miladrahimi/php-jwt)
[![Coverage Status](https://coveralls.io/repos/github/miladrahimi/php-jwt/badge.svg?branch=master)](https://coveralls.io/github/miladrahimi/php-jwt?branch=master)
[![License](https://poser.pugx.org/miladrahimi/php-jwt/license)](https://packagist.org/packages/miladrahimi/php-jwt)

# PHP-JWT

PHP-JWT is a package written in PHP programming language to encode (generate), decode (parse), verify and validate JWTs 
(JSON Web Tokens). It provides a fluent, easy-to-use, and object-oriented interface.

Confirmed by [JWT.io](https://jwt.io).

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

### Simple example

The following example shows how to generate a JWT using the HS256 algorithm and parse it.

```php
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;

// Signer and verifier is the same HS256
$signer = new HS256('12345678901234567890123456789012');

// Generate a token
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 666, 'is-admin' => true]);

// Parse the token
$parser = new Parser($signer);
$claims = $parser->parse($jwt);

echo $claims; // ['id' => 666, 'is-admin' => true]
```

### HMAC Algorithms

HMAC algorithms are symmetric, the same algorithm can both sign and verify JWTs. This package supports HS256, HS384, and HS512 of HMAC algorithms. The example mentioned above demonstrates how to use an HMAC algorithm to sign and verify a JWT.

### RSA Algorithms

RSA algorithms are asymmetric. A paired key is needed to sign and verify tokens. To sign a JWT, we use a private key, and to verify it, we use the related public key. These algorithms are useful when the authentication server cannot trust resource owners. Take a look at the following example:

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
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

$privateKey = new PrivateKey('/path/to/private.pem');
$publicKey = new PublicKey('/path/to/public.pem');

$signer = new RS256Signer($privateKey);
$verifier = new RS256Verifier($publicKey);

// Generate a token
$generator = new Generator($signer);
$jwt = $generator->generate(['id' => 666, 'is-admin' => true]);

// Parse the token
$parser = new Parser($verifier);
$claims = $parser->parse($jwt);

echo $claims; // ['sub' => 1, 'jti' => 2]
```

### Validation

In default, the package verifies the JWT signature, validate some of the public claims if they exist (using `DefaultValidator`), and parse the claims. If you have your custom claims, you can add their validation rules, as well. See this example:

```php
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;
use MiladRahimi\Jwt\Validator\Rules\GreaterThan;

$jwt = '...'; // Get the JWT from the user

$signer = new HS256('12345678901234567890123456789012');

// Add Validation (Extend the DefaultValidator)
$validator = new DefaultValidator();
$validator->addRule('is-admin', new EqualsTo(true));
$validator->addRule('id', new GreaterThan(600));

// Parse the token
$parser = new Parser($signer, $validator);
try {
    $claims = $parser->parse($jwt);
    echo $claims; // ['sub' => 1, 'jti' => 2]
} catch (ValidationException $e) {
    // Handle error.
}
```

In the example above, we used the `DefaultValidator`. This validator has some built-in rules for public claims. We also recommend you to use it for your validation. The `DefaultValidator` is a subclass of the `BaseValidator`. You can also use the `BaseValidator` for your validations, but you will lose the built-in rules, and you have to add all the rules yourself.

#### Rules

Validators use the rules to validate the claims. Each rule determines possible values for a claim. These are the built-in rules you can find under the namespace `MiladRahimi\Jwt\Validator\Rules`:
* ConsistsOf
* EqualsTo
* GreaterThan
* GreaterThanOrEqualTo
* IdenticalTo
* LessThan
* LessThanOrEqualTo
* NewerThan
* NewerThanOrSame
* NotEmpty
* NotNull
* OlderThan
* OlderThanOrSame

You can see their description in their class doc-block.

#### Required and Optional Rules

You can add a rule to a validator as required or optional. If the rule is required, validation will fail when the claim is not present in the JWT claims.

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
