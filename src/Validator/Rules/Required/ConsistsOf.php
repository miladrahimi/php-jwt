<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class ConsistsOf
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
 */
class ConsistsOf implements Rule
{
    /**
     * @var string
     */
    private $string;

    /**
     * @param string $string
     */
    public function __construct(string $string)
    {
        $this->string = $string;
    }

    /**
     * @inheritdoc
     */
    public function check($value, bool $exists): bool
    {
        return $exists && strpos($value ?: '', $this->string);
    }
}
