<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Cryptography\Verifier;
use Throwable;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * @var string
     */
    protected $key = '12345678901234567890123456789012';

    /**
     * @var RsaPrivateKey
     */
    protected $privateKey;

    /**
     * @var RsaPublicKey
     */
    protected $publicKey;

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
    public function setUp(): void
    {
        parent::setUp();

        $this->privateKey = new RsaPrivateKey(__DIR__ . '/../resources/test/keys/rsa-private.pem');

        $this->publicKey = new RsaPublicKey(__DIR__ . '/../resources/test/keys/rsa-public.pem');

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

    protected function expectExceptionMessageFormat(string $format)
    {
        if (method_exists($this, 'expectExceptionMessageMatches')) {
            $this->expectExceptionMessageMatches($format);
        } else {
            $this->expectExceptionMessageRegExp($format);
        }
    }
}
