<?php

namespace MiladRahimi\Jwt\Tests\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\DefaultValidator;
use Throwable;

class DefaultValidatorTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_with_no_claim_it_should_pass()
    {
        $validator = new DefaultValidator();
        $validator->validate([]);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_with_exp_it_should_pass_with_unexpired_exp()
    {
        $validator = new DefaultValidator();
        $validator->validate([
            'exp' => time() + 60 * 60 * 24,
        ]);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_with_exp_it_should_fail_with_expired_exp()
    {
        $validator = new DefaultValidator();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageFormat('/^The `exp` must be newer than `.+`.$/');
        $validator->validate([
            'exp' => time() - 60 * 60 * 24,
        ]);
    }

    /**
     * @throws Throwable
     */
    public function test_with_nbf_it_should_pass_with_earlier_time()
    {
        $validator = new DefaultValidator();
        $validator->validate([
            'nbf' => time() - 60 * 60 * 24,
        ]);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_with_nbf_it_should_fail_with_later_time()
    {
        $validator = new DefaultValidator();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageFormat('/^The `nbf` must be older than or same `.+`.$/');
        $validator->validate([
            'nbf' => time() + 60 * 60 * 24,
        ]);
    }

    /**
     * @throws Throwable
     */
    public function test_with_iat_it_should_pass_with_earlier_time()
    {
        $validator = new DefaultValidator();
        $validator->validate([
            'iat' => time() - 60 * 60 * 24,
        ]);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_with_iat_it_should_fail_with_later_time()
    {
        $validator = new DefaultValidator();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageFormat('/^The `iat` must be older than or same `.+`.$/');
        $validator->validate([
            'iat' => time() + 60 * 60 * 24,
        ]);
    }
}
