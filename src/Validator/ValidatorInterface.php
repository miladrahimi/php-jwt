<?php

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Interface ValidatorInterface
 *
 * @package MiladRahimi\Jwt\Validator
 */
interface ValidatorInterface
{
    /**
     * Verify claims
     *
     * @param string[] $claims
     * @throws ValidationException
     */
    public function validate(array $claims = []);
}
