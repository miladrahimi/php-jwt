<?php

namespace MiladRahimi\Jwt\Tests\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\DefaultValidator;

class DefaultValidatorTest extends TestCase
{
    public function test_with_no_claim_it_should_pass()
    {
        $validator = new DefaultValidator();
        $validator->validate([]);

        $this->assertTrue(true);
    }

    public function test_with_exp_it_should_pass_with_unexpired_exp()
    {
        $validator = new DefaultValidator();
        $validator->validate([
            'exp' => time() + 60 * 60 * 24,
        ]);

        $this->assertTrue(true);
    }

    public function test_with_exp_it_should_fail_with_expired_exp()
    {
        $validator = new DefaultValidator();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageRegExp('/^The `exp` must be newer than `.+`.$/');
        $validator->validate([
            'exp' => time() - 60 * 60 * 24,
        ]);
    }

    public function test_with_nbf_it_should_pass_with_earlier_time()
    {
        $validator = new DefaultValidator();
        $validator->validate([
            'nbf' => time() - 60 * 60 * 24,
        ]);

        $this->assertTrue(true);
    }

    public function test_with_nbf_it_should_fail_with_later_time()
    {
        $validator = new DefaultValidator();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageRegExp('/^The `nbf` must be older than or equal to `.+`.$/');
        $validator->validate([
            'nbf' => time() + 60 * 60 * 24,
        ]);
    }

    public function test_with_iat_it_should_pass_with_earlier_time()
    {
        $validator = new DefaultValidator();
        $validator->validate([
            'iat' => time() - 60 * 60 * 24,
        ]);

        $this->assertTrue(true);
    }

    public function test_with_iat_it_should_fail_with_later_time()
    {
        $validator = new DefaultValidator();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageRegExp('/^The `iat` must be older than or equal to `.+`.$/');
        $validator->validate([
            'iat' => time() + 60 * 60 * 24,
        ]);
    }
}
