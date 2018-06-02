<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 00:13
 */

namespace MiladRahimi\Jwt\Cryptography;

interface Signer
{
    /**
     * Get algorithm name
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Sign data
     *
     * @param string $data
     * @return string
     */
    public function sign(string $data): string;
}