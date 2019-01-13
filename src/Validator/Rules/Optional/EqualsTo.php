<?php

namespace MiladRahimi\Jwt\Validator\Rules\Optional;

use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class EqualsTo
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Optional
 */
class EqualsTo implements Rule
{
    /**
     * @var mixed
     */
    private $expectedValue;

    /**
     * @param mixed $expectedValue
     */
    public function __construct($expectedValue)
    {
        $this->expectedValue = $expectedValue;
    }

    /**
     * @inheritdoc
     */
    public function check($value, bool $exists): bool
    {
        return $exists == false || $this->expectedValue == $value;
    }
}
