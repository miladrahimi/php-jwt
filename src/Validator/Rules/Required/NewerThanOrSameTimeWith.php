<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

/**
 * Class NewerThanOrSameTimeWith
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
 */
class NewerThanOrSameTimeWith extends GreaterThanOrEqualTo
{
    /**
     * @param float $timestamp
     */
    public function __construct(float $timestamp)
    {
        parent::__construct($timestamp);
    }
}
