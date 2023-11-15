<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Enums\PublicClaimNames;
use Throwable;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected array $sampleClaims = [];

    protected string $sampleJwt;

    /**
     * @throws Throwable
     */
    public function setUp(): void
    {
        parent::setUp();

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
