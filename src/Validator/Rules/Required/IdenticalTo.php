<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class IdenticalTo
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
 */
class IdenticalTo implements Rule
{
    /**
     * @var mixed
     */
    private $expectedValueAndType;

    /**
     * @param mixed $expectedValueAndType
     */
    public function __construct($expectedValueAndType)
    {
        $this->expectedValueAndType = $expectedValueAndType;
    }

    /**
     * @inheritdoc
     */
    public function check($value, bool $exists): bool
    {
        return $exists && $this->expectedValueAndType === $value;
    }
}
