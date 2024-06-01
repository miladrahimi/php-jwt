<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * It checks if the claim is not null
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
