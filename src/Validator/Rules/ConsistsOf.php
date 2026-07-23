<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Checks whether the claim contains the given substring.
 */
class ConsistsOf implements Rule
{
    private string $substr;

    public function __construct(string $substr)
    {
        $this->substr = $substr;
    }

    /**
     * {@inheritDoc}
     */
    public function validate(string $name, $value)
    {
        if (strpos($value, $this->substr) === false) {
            $message = "The `$name` must consist of `$this->substr`.";

            throw new ValidationException($message);
        }
    }
}
