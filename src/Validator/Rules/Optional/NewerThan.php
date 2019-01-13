<?php

namespace MiladRahimi\Jwt\Validator\Rules\Optional;

/**
 * Class NewerThan
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Optional
 */
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
