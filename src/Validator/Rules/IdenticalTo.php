<?php

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class IdenticalTo
 * It checks if the claim is identical to the given value (and its type)
 *
 * @package MiladRahimi\Jwt\Validator\Rules
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
     * @inheritdoc
     */
    public function validate(string $name, $value)
    {
        if ($this->value !== $value) {
            $message = "The `$name` must be identical to `$this->value`.";
            throw new ValidationException($message);
        }
    }
}
