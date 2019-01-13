<?php

namespace MiladRahimi\Jwt\Validator\Rules\Optional;

/**
 * Class NewerThanOrSameTimeWith
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Optional
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
