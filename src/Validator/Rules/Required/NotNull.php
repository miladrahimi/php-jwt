<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/16/2018 AD
 * Time: 00:42
 */

namespace MiladRahimi\Jwt\Validator\Rules\Required;

use MiladRahimi\Jwt\Validator\Rule;

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