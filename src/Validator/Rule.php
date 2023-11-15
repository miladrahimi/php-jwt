<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Interface Rule
 *
 * @package MiladRahimi\Jwt\Validator
 */
interface Rule
{
    /**
     * Validate given value
     *
     * @param string $name
     * @param $value
     * @throws ValidationException
     */
    public function validate(string $name, $value);
}
