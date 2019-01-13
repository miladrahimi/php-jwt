<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class NotNull
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
 */
class NotNull implements Rule
{
    /**
     * @inheritdoc
     */
    public function check($value, bool $exists): bool
    {
        return $exists && $value !== null;
    }
}
