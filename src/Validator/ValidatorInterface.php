<?php

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Interface ValidatorInterface
 *
 * @package MiladRahimi\Jwt\Validator
 */
interface ValidatorInterface
{
    /**
     * Add a new rule
     *
     * @param string $claimName
     * @param Rule $rule
     */
    public function addRule(string $claimName, Rule $rule);

    /**
     * Clean added rules for given claim
     *
     * @param string $claimName
     */
    public function cleanRules(string $claimName);

    /**
     * Verify claims
     *
     * @param string[] $claims
     * @throws ValidationException
     */
    public function validate(array $claims = []);
}
