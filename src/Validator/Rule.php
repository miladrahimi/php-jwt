<?php

namespace MiladRahimi\Jwt\Validator;

/**
 * Interface Rule
 *
 * @package MiladRahimi\Jwt\Validator
 */
interface Rule
{
    /**
     * Check value
     *
     * @param $value
     * @param bool $exists
     * @return bool
     */
    public function check($value, bool $exists): bool;
}
