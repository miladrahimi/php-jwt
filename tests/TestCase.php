<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Enums\PublicClaimNames;
use Throwable;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected HmacKey $key;
    protected RsaPrivateKey $rsaPrivateKey;
    protected RsaPublicKey $rsaPublicKey;
    protected Signer $signer;
    protected Verifier $verifier;
    protected array $sampleClaims = [];
    protected string $sampleJwt;

    /**
     * @throws Throwable
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->rsaPrivateKey = new RsaPrivateKey(__DIR__ . '/../assets/keys/rsa-private.pem');
        $this->rsaPublicKey = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem');
        $this->key = HmacKey::create('12345678901234567890123456789012');
        $this->signer = $this->verifier = new HS256($this->key);

        $this->sampleClaims = [
            PublicClaimNames::SUBJECT => 666,
            PublicClaimNames::EXPIRATION_TIME => 1573166463 + 60 * 60 * 24,
            PublicClaimNames::NOT_BEFORE => 1573166463,
            PublicClaimNames::ISSUED_AT => 1573166463,
            PublicClaimNames::ISSUER => 'Test!',
        ];

        $this->sampleJwt = join('.', [
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
            'eyJzdWIiOjY2NiwiZXhwIjoxNTczMjUyODYzLCJuYmYiOjE1NzMxNjY0NjMsImlhdCI6MTU3MzE2NjQ2MywiaXNzIjoiVGVzdCEifQ',
            'CpOJ34DnOpG1lnSgmUpoCby8jQW7LiYeNMSLNEEMiuY'
        ]);
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
