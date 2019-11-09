<?php

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class NotNull
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class NotNull implements Rule
{
    /**
     * @inheritdoc
     */
    public function validate(string $name, $value)
    {
        if ($value === null) {
            $message = "The `$name` must not be null.";
            throw new ValidationException($message);
        }
    }
}
