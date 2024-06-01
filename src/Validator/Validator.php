<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Validation is responsible for validating extracted claims from JWTs.
 */
interface Validator
{
    /**
     * Validate the given claims
     *
     * @param string[] $claims
     * @throws ValidationException
     */
    public function validate(array $claims);
}
