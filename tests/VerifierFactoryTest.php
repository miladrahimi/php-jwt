<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests;

use InvalidArgumentException;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\NoKidException;
use MiladRahimi\Jwt\Exceptions\VerifierNotFoundException;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\VerifierFactory;
use stdClass;
use Throwable;

class VerifierFactoryTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_getVerifier_it_should_return_the_right_verifier()
    {
        $privateKey = new RsaPrivateKey(
            __DIR__ . '/../assets/keys/rsa-private.pem',
            '',
            'key-1'
        );
        $publicKey = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem', 'key-1');

        $generator = new Generator(new RS256Signer($privateKey));
        $jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

        $verifierFactory = new VerifierFactory([
            new RS256Verifier($publicKey),
        ]);

        $verifier = $verifierFactory->getVerifier($jwt);
        $this->assertEquals($publicKey->getId(), $verifier->kid());
    }

    /**
     * @throws Throwable
     */
    public function test_getVerifier_for_a_jwt_without_kid()
    {
        $verifierFactory = new VerifierFactory([]);

        $this->expectException(NoKidException::class);
        $noKidJwt = join('.', [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9',
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ',
            'zWb5oOGhQNCf39ahmFofCRJhzWTFFPMdKrzro5XGq5U',
        ]);
        $verifierFactory->getVerifier($noKidJwt);

        $this->expectException(VerifierNotFoundException::class);
        $differentKidJwt = join('.', [
            'eyJ0eXAiOiJKV1QiLCJraWQiOiJyYW5kb20iLCJhbGciOiJIUzI1NiJ9',
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ',
            'tGm81161CtfqSi0iKKC4E7afIxTjiEPY_UVb-knYFa4',
        ]);
        $verifierFactory->getVerifier($differentKidJwt);

        $this->expectException(InvalidTokenException::class);
        $noKidJwt = join('.', [
            'eyJ0eXAiOiJKV1QiLCJraWQiOiJyYW5kb20iLCJhbGciOiJIUzI1NiJ9',
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ',
        ]);
        $verifierFactory->getVerifier($noKidJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_getVerifier_for_a_jwt_with_a_different_kid()
    {
        $publicKey = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem', 'key-1');

        $verifierFactory = new VerifierFactory([
            new RS256Verifier($publicKey),
        ]);

        $this->expectException(VerifierNotFoundException::class);
        $differentKidJwt = join('.', [
            'eyJ0eXAiOiJKV1QiLCJraWQiOiJyYW5kb20iLCJhbGciOiJIUzI1NiJ9',
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ',
            'tGm81161CtfqSi0iKKC4E7afIxTjiEPY_UVb-knYFa4',
        ]);
        $verifierFactory->getVerifier($differentKidJwt);

        $this->expectException(InvalidTokenException::class);
        $noKidJwt = join('.', [
            'eyJ0eXAiOiJKV1QiLCJraWQiOiJyYW5kb20iLCJhbGciOiJIUzI1NiJ9',
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ',
        ]);
        $verifierFactory->getVerifier($noKidJwt);
    }

    /**
     * A header whose `kid` field is not a string (e.g. an array) must be
     * rejected cleanly instead of raising a PHP type error.
     *
     * @throws Throwable
     */
    public function test_getVerifier_for_a_jwt_with_non_string_kid()
    {
        $verifierFactory = new VerifierFactory([]);

        $header = rtrim(strtr(base64_encode('{"typ":"JWT","kid":["evil"],"alg":"HS256"}'), '+/', '-_'), '=');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT header `kid` field must be a string.');
        $verifierFactory->getVerifier("$header.payload.signature");
    }

    /**
     * @throws Throwable
     */
    public function test_getVerifier_for_an_invalid_jwt()
    {
        $verifierFactory = new VerifierFactory([]);

        $this->expectException(InvalidTokenException::class);
        $invalidJwt = join('.', [
            'eyJ0eXAiOiJKV1QiLCJraWQiOiJyYW5kb20iLCJhbGciOiJIUzI1NiJ9',
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ',
        ]);
        $verifierFactory->getVerifier($invalidJwt);
    }

    public function test_getting_verifier_with_unsupported_verifier_type()
    {
        $this->expectException(InvalidArgumentException::class);
        /** @noinspection PhpParamsInspection */
        new VerifierFactory([new stdClass()]);
    }
}
