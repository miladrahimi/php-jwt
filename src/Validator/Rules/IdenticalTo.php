<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Checks whether the claim is identical to the given value (including its type).
 */
class IdenticalTo implements Rule
{
    /**
     * @var mixed
     */
    private $value;

    /**
     * @param mixed $value
     */
    public function __construct($value)
    {
        $this->value = $value;
    }

    /**
     * {@inheritDoc}
     */
    public function validate(string $name, $value)
    {
        if ($this->value !== $value) {
            $message = "The `$name` must be identical to `$this->value`.";
            throw new ValidationException($message);
        }
    }
}
