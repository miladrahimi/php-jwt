<?php

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class ConsistsOf
 * It checks if the claim consists of the given substr
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class ConsistsOf implements Rule
{
    /**
     * @var string
     */
    private $substr;

    /**
     * @param string $substr
     */
    public function __construct(string $substr)
    {
        $this->substr = $substr;
    }

    /**
     * @inheritdoc
     */
    public function validate(string $name, $value)
    {
        if (strpos($value, $this->substr) === false) {
            $message = "The `$name` must consist of `$this->substr`.";
            throw new ValidationException($message);
        }
    }
}
