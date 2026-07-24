<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Validator is responsible for validating the claims extracted from JWTs.
 */
interface Validator
{
    /**
     * Validates the given claims.
     *
     * @param array<int|string, mixed> $claims
     *
     * @throws ValidationException
     *
     * @return void
     */
    public function validate(array $claims);
}
