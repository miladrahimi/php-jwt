<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/16/2018 AD
 * Time: 00:27
 */

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

interface ValidatorInterface
{
    /**
     * Add a new rule
     *
     * @param string $claimName
     * @param Rule $rule
     */
    public function addRule(string $claimName, Rule $rule): void;

    /**
     * Clean added rules for given claim
     *
     * @param string $claimName
     */
    public function cleanRules(string $claimName): void;

    /**
     * Verify claims
     *
     * @param string[] $claims
     * @throws ValidationException
     */
    public function validate(array $claims = []): void;
}