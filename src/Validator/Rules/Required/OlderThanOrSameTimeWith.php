<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

/**
 * Class OlderThanOrSameTimeWith
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
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
