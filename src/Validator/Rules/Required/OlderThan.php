<?php

namespace MiladRahimi\Jwt\Validator\Rules\Required;

/**
 * Class OlderThan
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Required
 */
class OlderThan extends LessThan
{
    /**
     * @param float $timestamp
     */
    public function __construct(float $timestamp)
    {
        parent::__construct($timestamp);
    }
}
