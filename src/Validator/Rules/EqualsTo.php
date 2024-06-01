<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * It checks if the claim equals to the given value
 */
class EqualsTo implements Rule
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
        if ($this->value != $value) {
            $message = "The `$name` must equal to `$this->value`.";
            throw new ValidationException($message);
        }
    }
}
