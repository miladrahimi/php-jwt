<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use Throwable;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * @var string
     */
    protected $key = '12345678901234567890123456789012';

    /**
     * @var Signer
     */
    protected $signer;

    /**
     * @var Verifier
     */
    protected $verifier;

    /**
     * @var array
     */
    protected $sampleClaims;

    /**
     * @var string
     */
    protected $sampleJwt;

    /**
     * @throws Throwable
     */
    public function setUp()
    {
        parent::setUp();

        $this->signer = $this->verifier = new HS256($this->key);

        $this->sampleClaims = [
            'sub' => 666,
            'exp' => 1573166463 + 60 * 60 * 24,
            'nbf' => 1573166463,
            'iat' => 1573166463,
            'iss' => 'Test!',
        ];

        $this->sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ.' .
            'CpOJ34DnOpG1lnSgmUpoCby8jQW7LiYeNMSLNEEMiuY';
    }

    /**
     * @return PrivateKey
     * @throws InvalidKeyException
     */
    protected function privateKey(): PrivateKey
    {
        return new PrivateKey(__DIR__ . '/../resources/test/keys/private.pem');
    }

    /**
     * @return PublicKey
     * @throws InvalidKeyException
     */
    protected function publicKey(): PublicKey
    {
        return new PublicKey(__DIR__ . '/../resources/test/keys/public.pem');
    }
}
