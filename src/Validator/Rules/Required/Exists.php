<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class Exists
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
 */
class Exists implements Rule
{
    /**
     * @inheritdoc
     */
    public function check($value, bool $exists): bool
    {
        return $exists;
    }
}
