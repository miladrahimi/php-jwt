<?php

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Interface Validator
 *
 * @package MiladRahimi\Jwt\Validator
 */
interface Validator
{
    /**
     * Validate given claims
     *
     * @param string[] $claims
     * @throws ValidationException
     */
    public function validate(array $claims = []);
}
