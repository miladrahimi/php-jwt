<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/16/2018 AD
 * Time: 00:40
 */

namespace MiladRahimi\Jwt\Validator;

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