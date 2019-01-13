<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

/**
 * Class NewerThan
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
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
