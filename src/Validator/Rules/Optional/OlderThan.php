<?php

namespace MiladRahimi\Jwt\Validator\Rules\Optional;

/**
 * Class OlderThan
 *
 * @package MiladRahimi\Jwt\Validator\Rules\Optional
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
