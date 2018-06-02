<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/16/2018 AD
 * Time: 00:42
 */

namespace MiladRahimi\Jwt\Validator\Rules\Optional;

class NewerThan extends GreaterThan
{
    /**
     * @param float $timestamp
     */
    public function __construct(float $timestamp)
    {
        parent::__construct($timestamp);
    }
}