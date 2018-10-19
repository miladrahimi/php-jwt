<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 00:39
 */

namespace MiladRahimi\Jwt\Base64;

interface Base64ParserInterface
{
    /**
     * Encode data by Base64 algorithm
     *
     * @param string $data
     * @return string
     */
    public function encode(string $data): string;

    /**
     * Decode Base64-encoded data to plain text
     *
     * @param string $data
     * @return string
     */
    public function decode(string $data): string;
}