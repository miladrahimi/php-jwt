<?php

namespace MiladRahimi\Jwt\Validator\Rules\Optional;

/**
 * Class OlderThanOrSameTimeWith
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Optional
 */
class OlderThanOrSameTimeWith extends LessThanOrEqualTo
{
    /**
     * @param float $timestamp
     */
    public function __construct(float $timestamp)
    {
        parent::__construct($timestamp);
    }
}
