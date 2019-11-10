<?php

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class NotEmpty
 * It checks if the claim is not empty
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class NotEmpty implements Rule
{
    /**
     * @inheritdoc
     */
    public function validate(string $name, $value)
    {
        if (empty($value)) {
            $message = "The `$name` must not be empty.";
            throw new ValidationException($message);
        }
    }
}
